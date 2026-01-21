#!/usr/bin/env python3
import argparse
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

# Mantis -> Tracklet mapping
MANTIS_STATUS_TO_TRACKLET = {
    10: "open",
    20: "open",
    30: "open",
    40: "open",
    50: "in_progress",
    80: "closed",
    90: "closed",
}
MANTIS_PRIORITY_TO_TRACKLET = {
    10: "low",
    20: "low",
    30: "medium",
    40: "high",
    50: "urgent",
    60: "urgent",
}

def iso_utc_from_unix(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return None

def fetchall_dict(con: sqlite3.Connection, sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
    cur = con.cursor()
    cur.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]

def get_one(con: sqlite3.Connection, sql: str, params: Tuple = ()) -> Optional[Tuple]:
    cur = con.cursor()
    cur.execute(sql, params)
    return cur.fetchone()

def build_tracklet_user_map(tracklet: sqlite3.Connection) -> Dict[str, int]:
    """
    email(lower) -> users.id
    """
    m: Dict[str, int] = {}
    for uid, email in tracklet.execute("SELECT id, email FROM users"):
        if email:
            m[email.strip().lower()] = int(uid)
    return m

def build_tracklet_project_map(tracklet: sqlite3.Connection) -> Dict[str, int]:
    """
    project name (lower) -> projects.id
    """
    m: Dict[str, int] = {}
    for pid, name in tracklet.execute("SELECT id, name FROM projects"):
        if name:
            m[name.strip().lower()] = int(pid)
    return m

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, help="Path to mantis.sqlite")
    ap.add_argument("--dest", required=True, help="Path to tracklet sqlite db")
    ap.add_argument("--dry-run", action="store_true", help="Do not write anything")
    ap.add_argument("--dedupe", action="store_true",
                    help="Avoid duplicates by matching (project_id,title,created_at) for issues and (issue_id,author_id,created_at,body) for comments")
    ap.add_argument("--fallback-project-id", type=int, default=None,
                    help="If a Mantis project name is not found in Tracklet, use this project_id instead of skipping")
    ap.add_argument("--fallback-user-id", type=int, default=None,
                    help="If a Mantis user email is not found in Tracklet, use this user_id instead of skipping")
    args = ap.parse_args()

    src = sqlite3.connect(args.source)
    src.row_factory = sqlite3.Row

    dest = sqlite3.connect(args.dest)
    dest.row_factory = sqlite3.Row
    dest.execute("PRAGMA foreign_keys = ON;")

    # Sanity: ensure destination tables exist
    needed_dest_tables = {"issues", "issue_comments", "users", "projects"}
    dest_tables = {r[0] for r in dest.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_dest = needed_dest_tables - dest_tables
    if missing_dest:
        raise RuntimeError(f"Destination missing tables: {sorted(missing_dest)}")

    # Build mapping of Tracklet IDs
    tracklet_user_by_email = build_tracklet_user_map(dest)
    tracklet_project_by_name = build_tracklet_project_map(dest)

    # Build Mantis project name by id
    mantis_projects = fetchall_dict(src, "SELECT id, name FROM mantis_project_table")
    mantis_project_name_by_id = {int(p["id"]): (p.get("name") or "").strip() for p in mantis_projects}

    # Build Mantis user email by id
    mantis_users = fetchall_dict(src, "SELECT id, email FROM mantis_user_table")
    mantis_user_email_by_id = {int(u["id"]): (u.get("email") or "").strip().lower() for u in mantis_users}

    # Load issues + text
    bugs = fetchall_dict(src, """
        SELECT b.id, b.project_id, b.reporter_id, b.handler_id, b.priority, b.status, b.summary,
               b.bug_text_id, b.date_submitted, b.last_updated,
               t.description AS descr, t.steps_to_reproduce AS steps, t.additional_information AS addi
        FROM mantis_bug_table b
        LEFT JOIN mantis_bug_text_table t ON t.id = b.bug_text_id
        ORDER BY b.id
    """)

    notes = fetchall_dict(src, """
        SELECT n.id, n.bug_id, n.reporter_id, n.date_submitted, nt.note
        FROM mantis_bugnote_table n
        LEFT JOIN mantis_bugnote_text_table nt ON nt.id = n.bugnote_text_id
        ORDER BY n.id
    """)

    print(f"Loaded from source: issues={len(bugs)}, comments={len(notes)}")
    print(f"Tracklet available: users={len(tracklet_user_by_email)}, projects={len(tracklet_project_by_name)}")

    # Transaction
    if not args.dry_run:
        dest.execute("BEGIN")

    issue_map_mantis_to_tracklet: Dict[int, int] = {}

    imported_issues = skipped_issues = 0
    imported_comments = skipped_comments = 0

    try:
        # ---- Insert issues ----
        for b in bugs:
            mantis_issue_id = int(b["id"])
            mantis_project_id = int(b["project_id"])
            mantis_reporter_id = int(b.get("reporter_id") or 0)
            mantis_handler_id = int(b.get("handler_id") or 0) if b.get("handler_id") else 0

            mantis_project_name = mantis_project_name_by_id.get(mantis_project_id, "").strip()
            tracklet_project_id = tracklet_project_by_name.get(mantis_project_name.lower())

            if tracklet_project_id is None:
                if args.fallback_project_id is not None:
                    tracklet_project_id = args.fallback_project_id
                else:
                    skipped_issues += 1
                    continue

            reporter_email = mantis_user_email_by_id.get(mantis_reporter_id, "")
            reporter_id = tracklet_user_by_email.get((reporter_email or "").lower())
            if reporter_id is None:
                if args.fallback_user_id is not None:
                    reporter_id = args.fallback_user_id
                else:
                    skipped_issues += 1
                    continue

            assignee_id: Optional[int] = None
            if mantis_handler_id:
                assignee_email = mantis_user_email_by_id.get(mantis_handler_id, "")
                assignee_id = tracklet_user_by_email.get((assignee_email or "").lower())
                if assignee_id is None and args.fallback_user_id is not None:
                    # Only apply fallback to assignee if requested
                    assignee_id = args.fallback_user_id
                if assignee_id == reporter_id:
                    # ok; no change
                    pass

            title = (b.get("summary") or "").strip() or f"Mantis Issue {mantis_issue_id}"

            parts = []
            if b.get("descr"):
                parts.append(b["descr"])
            if b.get("steps"):
                parts.append("\n\nSteps to reproduce:\n" + b["steps"])
            if b.get("addi"):
                parts.append("\n\nAdditional information:\n" + b["addi"])
            description = "".join(parts).strip() or None

            status = MANTIS_STATUS_TO_TRACKLET.get(int(b.get("status") or 10), "open")
            priority = MANTIS_PRIORITY_TO_TRACKLET.get(int(b.get("priority") or 30), "medium")

            created_at = iso_utc_from_unix(b.get("date_submitted"))
            updated_at = iso_utc_from_unix(b.get("last_updated"))
            closed_at = updated_at if status == "closed" else None

            if args.dedupe and not args.dry_run:
                row = get_one(
                    dest,
                    "SELECT id FROM issues WHERE project_id=? AND title=? AND created_at=?",
                    (tracklet_project_id, title, created_at),
                )
                if row:
                    issue_id = int(row[0])
                    issue_map_mantis_to_tracklet[mantis_issue_id] = issue_id
                    skipped_issues += 1
                    continue

            if args.dry_run:
                issue_id = -1
            else:
                cur = dest.cursor()
                cur.execute(
                    """
                    INSERT INTO issues
                      (project_id,title,description,status,priority,reporter_id,assignee_id,created_at,updated_at,closed_at)
                    VALUES
                      (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        tracklet_project_id,
                        title,
                        description,
                        status,
                        priority,
                        reporter_id,
                        assignee_id,
                        created_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        updated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        closed_at,
                    ),
                )
                issue_id = int(cur.lastrowid)

            issue_map_mantis_to_tracklet[mantis_issue_id] = issue_id
            imported_issues += 1

        # ---- Insert comments ----
        for n in notes:
            mantis_note_id = int(n["id"])
            mantis_issue_id = int(n["bug_id"])
            issue_id = issue_map_mantis_to_tracklet.get(mantis_issue_id)

            # If the issue was skipped, skip its comments too
            if issue_id is None:
                skipped_comments += 1
                continue

            body = (n.get("note") or "").strip()
            if not body:
                skipped_comments += 1
                continue

            mantis_author_id = int(n.get("reporter_id") or 0)
            author_email = mantis_user_email_by_id.get(mantis_author_id, "")
            author_id = tracklet_user_by_email.get((author_email or "").lower())

            if author_id is None:
                if args.fallback_user_id is not None:
                    author_id = args.fallback_user_id
                else:
                    skipped_comments += 1
                    continue

            created_at = iso_utc_from_unix(n.get("date_submitted"))

            if args.dedupe and not args.dry_run:
                if created_at:
                    row = get_one(
                        dest,
                        "SELECT 1 FROM issue_comments WHERE issue_id=? AND author_id=? AND created_at=? AND body=?",
                        (issue_id, author_id, created_at, body),
                    )
                else:
                    row = get_one(
                        dest,
                        "SELECT 1 FROM issue_comments WHERE issue_id=? AND author_id=? AND body=?",
                        (issue_id, author_id, body),
                    )
                if row:
                    skipped_comments += 1
                    continue

            if not args.dry_run:
                dest.execute(
                    "INSERT INTO issue_comments (issue_id, author_id, body, created_at) VALUES (?,?,?,?)",
                    (issue_id, author_id, body, created_at or datetime.now(timezone.utc).isoformat(timespec="seconds")),
                )

            imported_comments += 1

        if not args.dry_run:
            dest.commit()

        print("✅ Done.")
        print(f"Issues: imported={imported_issues}, skipped={skipped_issues}")
        print(f"Comments: imported={imported_comments}, skipped={skipped_comments}")

        if skipped_issues or skipped_comments:
            print("\nWhy skipped happens:")
            print("- Missing project mapping (Mantis project name not found in Tracklet)")
            print("- Missing user mapping (Mantis user email not found in Tracklet)")
            print("\nFix options:")
            print("- Create matching users/projects in Tracklet first")
            print("- Or rerun with --fallback-project-id and/or --fallback-user-id")

    except Exception:
        if not args.dry_run:
            dest.rollback()
        raise
    finally:
        src.close()
        dest.close()

if __name__ == "__main__":
    main()
