from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Optional
from werkzeug.security import generate_password_hash


# -------------------------------------------------------
# DB path / connection
# -------------------------------------------------------

from config import settings

def get_db_path() -> str:
    return settings.DB_PATH


def _ensure_parent(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    _ensure_parent(db_path)

    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def transaction():
    conn = get_connection()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# -------------------------------------------------------
# Generic helpers
# -------------------------------------------------------

def db_read_one(sql: str, params: tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchone()
    finally:
        conn.close()


def db_read_all(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()


def db_write(sql: str, params: tuple[Any, ...] = ()) -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# -------------------------------------------------------
# Schema / init
# -------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',     -- admin|pm|user
  photo_path TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,

  -- GitHub repo reference (optional)
  github_owner TEXT,
  github_repo TEXT,
  github_default_branch TEXT DEFAULT 'main',
  github_repo_url TEXT,

  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open',     -- open|in_progress|blocked|closed
  priority TEXT NOT NULL DEFAULT 'medium', -- low|medium|high|urgent
  reporter_id INTEGER NOT NULL,
  assignee_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  due_date TEXT NOT NULL DEFAULT (date('now','+14 days')),
  closed_at TEXT,
  FOREIGN KEY(project_id) REFERENCES projects(id),
  FOREIGN KEY(reporter_id) REFERENCES users(id),
  FOREIGN KEY(assignee_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS issue_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  issue_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(issue_id) REFERENCES issues(id),
  FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS issue_watchers (
  issue_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (issue_id, user_id),
  FOREIGN KEY(issue_id) REFERENCES issues(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS issue_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  issue_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  meta_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(issue_id) REFERENCES issues(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_issues_assignee ON issues(assignee_id, status);
CREATE INDEX IF NOT EXISTS idx_issues_project ON issues(project_id, status);
"""

def init_db() -> None:
    with transaction() as cur:
        cur.executescript(SCHEMA_SQL)
    migrate_add_watcher_id()

# -------------------------------------------------------
# Bootstrap
# -------------------------------------------------------

def bootstrap_if_empty() -> None:
    """If DB has no users, create default admin + default project."""
    any_user = db_read_one("SELECT id FROM users LIMIT 1")
    if any_user:
        return

    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@local").strip().lower()
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin1234")
    name = os.getenv("BOOTSTRAP_ADMIN_NAME", "Admin")

    db_write(
        "INSERT INTO users(email, password_hash, name, role) VALUES (?,?,?,?)",
        (email, generate_password_hash(password), name, "admin"),
    )
    db_write("INSERT INTO projects(name, description) VALUES (?,?)", ("General", "Default project"))


def migrate_add_watcher_id() -> None:
    with transaction() as cur:
        cols = cur.execute("PRAGMA table_info(issues)").fetchall()
        names = {c[1] for c in cols}
        if "watcher_id" not in names:
            cur.execute("ALTER TABLE issues ADD COLUMN watcher_id INTEGER;")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_issues_watcher ON issues(watcher_id);")
# -------------------------------------------------------
# Search
# -------------------------------------------------------
    
def search_issues(q: str, limit: int = 50) -> list[sqlite3.Row]:
    like = f"%{q.strip()}%"
    return db_read_all(
        """
        SELECT i.id, i.title, i.status, i.priority, p.name AS project_name
        FROM issues i
        JOIN projects p ON p.id=i.project_id
        WHERE (i.title LIKE ? OR i.description LIKE ?)
          AND p.is_active=1
        ORDER BY i.updated_at DESC
        LIMIT ?
        """,
        (like, like, limit),
    )


def search_projects(q: str, limit: int = 20) -> list[sqlite3.Row]:
    like = f"%{q.strip()}%"
    return db_read_all(
        """
        SELECT id, name, description, github_owner, github_repo
        FROM projects
        WHERE name LIKE ? AND is_active=1
        ORDER BY name
        LIMIT ?
        """,
        (like, limit),
    )

# -------------------------------------------------------
# Users
# -------------------------------------------------------

def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    return db_read_one("SELECT * FROM users WHERE id=? AND is_active=1", (user_id,))


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    return db_read_one("SELECT * FROM users WHERE lower(email)=lower(?) AND is_active=1", (email,))


def list_users_active() -> list[sqlite3.Row]:
    return db_read_all("SELECT id, name, email FROM users WHERE is_active=1 ORDER BY name")


def list_users_admin() -> list[sqlite3.Row]:
    return db_read_all("SELECT id, name, email, role, is_active, created_at FROM users ORDER BY created_at DESC")


def create_user(name: str, email: str, role: str, password_hash: str) -> int:
    return db_write(
        "INSERT INTO users(email, password_hash, name, role) VALUES (?,?,?,?)",
        (email.strip().lower(), password_hash, name.strip(), role.strip()),
    )

def update_user(user_id: int, name: str, email: str, role: str, password_hash: str | None) -> None:
    if password_hash:
        db_write(
            "UPDATE users SET name=?, email=?, role=? , password_hash=? WHERE id=?",
            (name.strip(), email.strip().lower(), role.strip(), password_hash, user_id),
        )
    else:
        db_write(
            "UPDATE users SET name=?, email=?, role=? WHERE id=?",
            (name.strip(), email.strip().lower(), role.strip(), user_id),
        )

def update_user_info(
    user_id: int,
    name: str,
    email: str,
    role: str,
    password_hash: Optional[str] = None,
) -> None:
    if password_hash:
        db_write(
            """
            UPDATE users
            SET name=?, email=?, role=?, password_hash=?
            WHERE id=?
            """,
            (name.strip(), email.strip().lower(), role.strip(), password_hash, user_id),
        )
    else:
        db_write(
            """
            UPDATE users
            SET name=?, email=?, role=?
            WHERE id=?
            """,
            (name.strip(), email.strip().lower(), role.strip(), user_id),
        )

def list_users_without_welcome() -> list[sqlite3.Row]:
    return db_read_all(
        """
        SELECT *
        FROM users
        WHERE email LIKE '%@local'
           OR name = ''
        """
    )        
# -------------------------------------------------------
# Projects
# -------------------------------------------------------

def list_projects_active() -> list[sqlite3.Row]:
    return db_read_all("SELECT id, name FROM projects WHERE is_active=1 ORDER BY name")


def list_projects_admin() -> list[sqlite3.Row]:
    return db_read_all("SELECT * FROM projects ORDER BY created_at DESC")


def create_project(name: str, description: str) -> int:
    return db_write("INSERT INTO projects(name, description) VALUES (?,?)", (name.strip(), description.strip()))

def get_project(project_id: int) -> Optional[sqlite3.Row]:
    return db_read_one("SELECT * FROM projects WHERE id=?", (project_id,))


def update_project_github(project_id: int, owner: str, repo: str, branch: str, repo_url: str) -> None:
    db_write(
        """
        UPDATE projects
        SET github_owner=?, github_repo=?, github_default_branch=?, github_repo_url=?
        WHERE id=?
        """,
        (owner.strip() or None, repo.strip() or None, branch.strip() or "main", repo_url.strip() or None, project_id),
    )


def list_project_issues(project_id: int) -> list[sqlite3.Row]:
    return db_read_all(
        """
        SELECT i.*, u.name AS assignee_name
        FROM issues i
        LEFT JOIN users u ON u.id=i.assignee_id
        WHERE i.project_id=?
        ORDER BY
          CASE i.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'blocked' THEN 3 ELSE 4 END,
          CASE i.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          i.updated_at DESC
        """,
        (project_id,),
    )

def project_has_issues(project_id: int) -> bool:
    r = db_read_one("SELECT 1 FROM issues WHERE project_id=? LIMIT 1", (project_id,))
    return r is not None


def deactivate_project(project_id: int) -> None:
    db_write("UPDATE projects SET is_active=0 WHERE id=?", (project_id,))


def delete_project_hard(project_id: int) -> None:
    # Only safe if no issues
    db_write("DELETE FROM projects WHERE id=?", (project_id,))

# -------------------------------------------------------
# Issues
# -------------------------------------------------------

def get_my_tasks(user_id: int, *, include_closed: bool = False) -> list[sqlite3.Row]:
    where_extra = "" if include_closed else " AND i.status <> 'closed'"

    return db_read_all(
        f"""
        SELECT i.*, p.name AS project_name,
               au.name AS assignee_name
        FROM issues i
        JOIN projects p ON p.id=i.project_id
        LEFT JOIN users au ON au.id=i.assignee_id
        WHERE i.assignee_id=? {where_extra}
        ORDER BY
          CASE i.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'blocked' THEN 3 ELSE 4 END,
          CASE i.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          i.updated_at DESC
        """,
        (user_id,),
    )

def get_my_tasks_history(user_id: int) -> list[sqlite3.Row]:
    return db_read_all(
        """
        SELECT i.*, p.name AS project_name,
               au.name AS assignee_name
        FROM issues i
        JOIN projects p ON p.id=i.project_id
        LEFT JOIN users au ON au.id=i.assignee_id
        WHERE i.assignee_id=? AND i.status='closed'
        ORDER BY i.closed_at DESC, i.updated_at DESC
        """,
        (user_id,),
    )

def create_issue(project_id: int, title: str, description: str, priority: str,
                 reporter_id: int, assignee_id: Optional[int], due_date: str) -> int:
    return db_write(
        """
        INSERT INTO issues(project_id, title, description, priority, reporter_id, assignee_id, due_date)
        VALUES (?,?,?,?,?,?,?)
        """,
        (project_id, title.strip(), description.strip(), priority.strip(), reporter_id, assignee_id, due_date),
    )

def get_issue_view(issue_id: int) -> Optional[sqlite3.Row]:
    return db_read_one(
        """
        SELECT i.*, p.name AS project_name,
               ru.name AS reporter_name,
               au.name AS assignee_name, au.email AS assignee_email
        FROM issues i
        JOIN projects p ON p.id=i.project_id
        JOIN users ru ON ru.id=i.reporter_id
        LEFT JOIN users au ON au.id=i.assignee_id
        WHERE i.id=?
        """,
        (issue_id,),
    )

def get_issue_compact(issue_id: int) -> Optional[sqlite3.Row]:
    return db_read_one(
        """
        SELECT i.id, i.title, i.status, i.priority, i.assignee_id,
               p.name AS project_name
        FROM issues i
        JOIN projects p ON p.id=i.project_id
        WHERE i.id=?
        """,
        (issue_id,),
    )

def close_issue(issue_id: int) -> None:
    db_write(
        "UPDATE issues SET status='closed', closed_at=datetime('now'), updated_at=datetime('now') WHERE id=?",
        (issue_id,),
    )

def add_issue_file(issue_id: int, uploader_id: int, stored_name: str, original_name: str, mime_type: str, size_bytes: int) -> int:
    return db_write(
        """
        INSERT INTO issue_files(issue_id, uploader_id, stored_name, original_name, mime_type, size_bytes)
        VALUES (?,?,?,?,?,?)
        """,
        (issue_id, uploader_id, stored_name, original_name, mime_type, int(size_bytes or 0)),
    )

def list_issue_files(issue_id: int) -> list[sqlite3.Row]:
    return db_read_all(
        """
        SELECT f.*, u.name AS uploader_name
        FROM issue_files f
        JOIN users u ON u.id=f.uploader_id
        WHERE f.issue_id=?
        ORDER BY f.created_at DESC
        """,
        (issue_id,),
    )

def get_issue_file(file_id: int) -> Optional[sqlite3.Row]:
    return db_read_one("SELECT * FROM issue_files WHERE id=?", (file_id,))

def delete_issue_file(file_id: int):
    db_write("DELETE FROM issue_files WHERE id = ?", (file_id,))

def set_issue_status(issue_id: int, new_status: str) -> None:
    if new_status == "closed":
        db_write(
            "UPDATE issues SET status='closed', closed_at=datetime('now'), updated_at=datetime('now') WHERE id=?",
            (issue_id,),
        )
    else:
        db_write(
            "UPDATE issues SET status=?, closed_at=NULL, updated_at=datetime('now') WHERE id=?",
            (new_status, issue_id),
        )

def get_issue_notify_recipient(issue_id: int, actor_user_id: int) -> Optional[sqlite3.Row]:
    """
    If actor is reporter -> return assignee (if exists)
    If actor is assignee -> return reporter
    Else -> None
    """
    issue = db_read_one(
        "SELECT id, title, reporter_id, assignee_id FROM issues WHERE id=?",
        (issue_id,),
    )
    if not issue:
        return None

    reporter_id = int(issue["reporter_id"])
    assignee_id = issue["assignee_id"]
    assignee_id = int(assignee_id) if assignee_id is not None else None

    if actor_user_id == reporter_id:
        if not assignee_id:
            return None
        return get_user_by_id(assignee_id)

    if assignee_id and actor_user_id == assignee_id:
        return get_user_by_id(reporter_id)

    return None

def get_issue_by_number(issue_number: int) -> Optional[sqlite3.Row]:
    return get_issue_compact(issue_number)

def update_issue_due_date(issue_id: int, due_date: str) -> None:
    db_write(
        "UPDATE issues SET due_date=?, updated_at=datetime('now') WHERE id=?",
        (due_date, issue_id),
    )

def set_issue_assignee(issue_id: int, assignee_id: Optional[int]) -> None:
    db_write(
        "UPDATE issues SET assignee_id=?, updated_at=datetime('now') WHERE id=?",
        (assignee_id, issue_id),
    )

def get_project_name(project_id: int) -> str:
    row = db_read_one("SELECT name FROM projects WHERE id=?", (project_id,))
    return row["name"] if row else "Project"

def get_my_reported_issues(user_id: int, *, include_closed: bool = True) -> list[sqlite3.Row]:
    where_extra = "" if include_closed else " AND i.status <> 'closed'"
    return db_read_all(
        f"""
        SELECT i.*, p.name AS project_name,
               au.name AS assignee_name
        FROM issues i
        JOIN projects p ON p.id=i.project_id
        LEFT JOIN users au ON au.id=i.assignee_id
        WHERE i.reporter_id=? {where_extra}
        ORDER BY
          CASE i.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'blocked' THEN 3 ELSE 4 END,
          CASE i.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          i.updated_at DESC
        """,
        (user_id,),
    )    
# -------------------------------------------------------
# Comments
# -------------------------------------------------------

def list_comments(issue_id: int) -> list[sqlite3.Row]:
    return db_read_all(
        """
        SELECT c.*, u.name AS author_name
        FROM issue_comments c
        JOIN users u ON u.id=c.author_id
        WHERE c.issue_id=?
        ORDER BY c.created_at ASC
        """,
        (issue_id,),
    )


def add_comment(issue_id: int, author_id: int, body: str) -> int:
    return db_write(
        "INSERT INTO issue_comments(issue_id, author_id, body) VALUES (?,?,?)",
        (issue_id, author_id, body.strip()),
    )

# -------------------------------------------------------
# Roles
# -------------------------------------------------------
def list_roles_active() -> list[sqlite3.Row]:
    return db_read_all("SELECT id, name FROM roles WHERE is_active=1 ORDER BY name")

def list_roles_admin() -> list[sqlite3.Row]:
    return db_read_all("SELECT id, name, is_active, created_at FROM roles ORDER BY created_at DESC")

def add_role(name: str) -> int:
    return db_write("INSERT INTO roles(name, is_active) VALUES (?,1)", (name.strip(),))

def delete_role(name: str) -> None:
    # hard delete is ok (you can switch to soft delete if you prefer)
    db_write("DELETE FROM roles WHERE name=?", (name.strip(),))

def role_in_use(name: str) -> bool:
    row = db_read_one("SELECT 1 FROM users WHERE role=? LIMIT 1", (name.strip(),))
    return row is not None
# -------------------------------------------------------
# Watchers 
# -------------------------------------------------------

def set_issue_watcher(issue_id: int, watcher_id: Optional[int]) -> None:
    db_write(
        "UPDATE issues SET watcher_id=?, updated_at=datetime('now') WHERE id=?",
        (watcher_id, issue_id),
    )

def get_issue_watcher_user(issue_id: int) -> Optional[sqlite3.Row]:
    return db_read_one(
        """
        SELECT u.id, u.name, u.email
        FROM issues i
        JOIN users u ON u.id = i.watcher_id
        WHERE i.id=? AND i.watcher_id IS NOT NULL
        """,
        (issue_id,),
    )




# -------------------------------------------------------
# Events (audit)
# -------------------------------------------------------

def log_issue_event(issue_id: int, user_id: int, event_type: str, meta_json: Optional[str] = None) -> int:
    return db_write(
        "INSERT INTO issue_events(issue_id, user_id, event_type, meta_json) VALUES (?,?,?,?)",
        (issue_id, user_id, event_type, meta_json),
    )


def _column_exists(table: str, col: str) -> bool:
    rows = db_read_all(f"PRAGMA table_info({table})")
    return any(r["name"] == col for r in rows)


def migrate_db() -> None:
    """
    Safe schema migration for existing DBs.
    Adds GitHub columns to projects if they don't exist.
    """
    # If projects table doesn't exist yet, init_db() will create it with the new schema.
    tbl = db_read_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='projects'"
    )
    if not tbl:
        return

    alters: list[str] = []
    if not _column_exists("projects", "github_owner"):
        alters.append("ALTER TABLE projects ADD COLUMN github_owner TEXT;")
    if not _column_exists("projects", "github_repo"):
        alters.append("ALTER TABLE projects ADD COLUMN github_repo TEXT;")
    if not _column_exists("projects", "github_default_branch"):
        alters.append("ALTER TABLE projects ADD COLUMN github_default_branch TEXT DEFAULT 'main';")
    if not _column_exists("projects", "github_repo_url"):
        alters.append("ALTER TABLE projects ADD COLUMN github_repo_url TEXT;")

    if alters:
        with transaction() as cur:
            for sql in alters:
                cur.execute(sql)


    # create issue_files table if missing
    tbl = db_read_one("SELECT name FROM sqlite_master WHERE type='table' AND name='issue_files'")
    if not tbl:
        with transaction() as cur:
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS issue_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL,
            uploader_id INTEGER NOT NULL,
            stored_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            mime_type TEXT,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(issue_id) REFERENCES issues(id),
            FOREIGN KEY(uploader_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_issue_files_issue ON issue_files(issue_id, created_at);
            """)

        # roles table
    tbl = db_read_one("SELECT name FROM sqlite_master WHERE type='table' AND name='roles'")
    if not tbl:
        with transaction() as cur:
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """)
    #due date issues
    cols = db_read_all("PRAGMA table_info(issues)")
    colnames = {c["name"] for c in cols}
    if "due_date" not in colnames:
        with transaction() as cur:
            cur.execute("ALTER TABLE issues ADD COLUMN due_date TEXT")
        # set default for existing rows
        db_write("UPDATE issues SET due_date = date('now','+14 days') WHERE due_date IS NULL")



def ensure_default_roles() -> None:
    defaults = ["user", "pm", "admin"]
    for r in defaults:
        try:
            db_write("INSERT INTO roles(name, is_active) VALUES (?,1)", (r,))
        except sqlite3.IntegrityError:
            pass            

#Settings
def update_my_settings(user_id: int, name: str, role: str, password_hash: Optional[str]) -> None:
    if password_hash:
        db_write(
            "UPDATE users SET name=?, role=?, password_hash=? WHERE id=?",
            (name.strip(), role.strip(), password_hash, user_id),
        )
    else:
        db_write(
            "UPDATE users SET name=?, role=? WHERE id=?",
            (name.strip(), role.strip(), user_id),
        )


def delete_user_cascade(user_id: int, fallback_reporter_id: int) -> None:
    """
    Hard-delete user and cascade-clean related tables.
    Keeps issues alive:
      - if user was assignee -> set assignee_id NULL
      - if user was reporter -> reassign reporter_id to fallback_reporter_id
    """
    with transaction() as cur:
        # 1) Reassign issues to keep FK valid
        cur.execute(
            "UPDATE issues SET assignee_id=NULL, updated_at=datetime('now') WHERE assignee_id=?",
            (user_id,),
        )
        cur.execute(
            "UPDATE issues SET reporter_id=?, updated_at=datetime('now') WHERE reporter_id=?",
            (fallback_reporter_id, user_id),
        )

        # 2) Delete dependent rows (manual cascade)
        cur.execute("DELETE FROM issue_watchers WHERE user_id=?", (user_id,))
        cur.execute("DELETE FROM issue_comments WHERE author_id=?", (user_id,))
        cur.execute("DELETE FROM issue_events WHERE user_id=?", (user_id,))

        # If you have issue_files table, include it too:
        # cur.execute("DELETE FROM issue_files WHERE uploader_id=?", (user_id,))

        # 3) Finally delete the user
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))

        