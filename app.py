# app.py
from datetime import date, timedelta
from pathlib import Path
import sqlite3
import uuid

from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from flask import send_from_directory
from werkzeug.utils import secure_filename
from config import settings
from TrackletDB import (
    add_issue_file, add_role, deactivate_project, delete_project_hard, delete_role, ensure_default_roles, get_issue_file, get_issue_notify_recipient, init_db, bootstrap_if_empty,

    # users
    get_user_by_id, get_user_by_email, list_issue_files, list_roles_active, list_roles_admin,
    list_users_active, list_users_admin, create_user,

    # projects
    list_projects_active, list_projects_admin, create_project,
    get_project, list_project_issues, migrate_db, project_has_issues, role_in_use, search_issues, search_projects, set_issue_status, update_my_settings, update_project_github,

    # issues
    get_my_tasks, create_issue, get_issue_view, get_issue_compact, close_issue,

    # comments
    list_comments, add_comment,

    # events
    log_issue_event,

    # generic (small permission check query)
    db_read_one, update_user,
)

from TrackletMailer import (
    send_issue_assigned,
    send_issue_comment,
    send_issue_reminder,
    MailerError,
    is_configured as mail_is_configured,
    send_issue_status_changed,
)

from TrackletGitHub import get_releases, get_tags


# -------------------------------------------------
# App setup
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = settings.SECRET_KEY

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@app.context_processor
def inject_settings():
    return {"settings": settings}
# -------------------------------------------------
# User model
# -------------------------------------------------
class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.email = row["email"]
        self.name = row["name"]
        self.role = row["role"]
        self.photo_path = row["photo_path"]


@login_manager.user_loader
def load_user(user_id: str):
    row = get_user_by_id(int(user_id))
    return User(row) if row else None


def is_admin() -> bool:
    return current_user.is_authenticated and current_user.role == "admin"


# -------------------------------------------------
# Startup
# -------------------------------------------------
init_db()
migrate_db()
ensure_default_roles()
bootstrap_if_empty()


# -------------------------------------------------
# Auth
# -------------------------------------------------
@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("my_tasks"))
    return render_template("login.html")


@app.post("/login")
def login_post():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    row = get_user_by_email(email)
    if not row or not check_password_hash(row["password_hash"], password):
        flash("Invalid email or password", "error")
        return redirect(url_for("login"))

    login_user(User(row))
    return redirect(url_for("my_tasks"))


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# -------------------------------------------------
# Main
# -------------------------------------------------
@app.get("/")
@login_required
def home():
    return redirect(url_for("my_tasks"))


@app.get("/my-tasks")
@login_required
def my_tasks():
    issues = get_my_tasks(int(current_user.id))
    return render_template("my_tasks.html", issues=issues)

# -------------------------------------------------
# Search
# -------------------------------------------------
@app.get("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return render_template("search.html", q=q, issues=[], projects=[])
    issue_by_id = None
    if q.isdigit():
        issue_by_id = get_issue_compact(int(q))
    issues = search_issues(q, limit=50)
    projects = search_projects(q, limit=20)
    return render_template("search.html", q=q, issues=issues, projects=projects, issue_by_id=issue_by_id)

# -------------------------------------------------
# Files
# -------------------------------------------------

def _ensure_upload_dir() -> Path:
    p = Path(settings.UPLOAD_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p

def _issue_dir(issue_id: int) -> Path:
    base = _ensure_upload_dir()
    d = base / f"issue_{issue_id}"
    d.mkdir(parents=True, exist_ok=True)
    return d


@app.post("/issues/<int:issue_id>/upload")
@login_required
def issue_upload(issue_id: int):
    # ensure issue exists
    issue = get_issue_view(issue_id)
    if not issue:
        abort(404)

    f = request.files.get("file")
    if not f or not f.filename:
        flash("No file selected", "error")
        return redirect(url_for("issue_view", issue_id=issue_id))

    original = secure_filename(f.filename)
    ext = Path(original).suffix.lower()
    stored = f"{uuid.uuid4().hex}{ext}"

    target_dir = _issue_dir(issue_id)
    target_path = target_dir / stored

    f.save(target_path)

    size_bytes = target_path.stat().st_size
    mime = f.mimetype or ""

    add_issue_file(
        issue_id=issue_id,
        uploader_id=int(current_user.id),
        stored_name=stored,
        original_name=original,
        mime_type=mime,
        size_bytes=size_bytes,
    )

    log_issue_event(issue_id, int(current_user.id), "file_uploaded")
    flash("File uploaded", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))

@app.get("/files/<int:file_id>/download")
@login_required
def file_download(file_id: int):
    row = get_issue_file(file_id)
    if not row:
        abort(404)

    issue_id = int(row["issue_id"])
    directory = _issue_dir(issue_id)

    return send_from_directory(
        directory,
        row["stored_name"],
        as_attachment=True,
        download_name=row["original_name"],
    )

# -------------------------------------------------
# Projects
# -------------------------------------------------
@app.get("/projects")
@login_required
def projects_list():
    projects = list_projects_active()
    return render_template("projects.html", projects=projects)


@app.get("/projects/<int:project_id>")
@login_required
def project_view(project_id: int):
    proj = get_project(project_id)
    if not proj:
        abort(404)

    issues = list_project_issues(project_id)

    releases = []
    github_error = None

    owner = (proj["github_owner"] or "").strip()
    repo = (proj["github_repo"] or "").strip()

    if owner and repo:
        try:
            releases = get_releases(owner, repo, limit=10)
            if not releases:
                releases = get_tags(owner, repo, limit=10)
        except Exception as e:
            github_error = str(e)

    return render_template(
        "project_view.html",
        project=proj,
        issues=issues,
        releases=releases,
        github_error=github_error,
    )


# -------------------------------------------------
# Issues
# -------------------------------------------------
@app.get("/issues/new")
@login_required
def issue_new():
    default_due = (date.today() + timedelta(days=14)).isoformat()
    return render_template(
        "issue_new.html",
        projects=list_projects_active(),
        users=list_users_active(),
        default_due=default_due,
    )


@app.post("/issues/new")
@login_required
def issue_new_post():
    title = request.form.get("title", "").strip()
    due_date = request.form.get("due_date") or (date.today() + timedelta(days=14)).isoformat()
    if not title:
        flash("Title is required", "error")
        return redirect(url_for("issue_new"))

    project_id = int(request.form.get("project_id"))
    description = request.form.get("description", "").strip()
    priority = request.form.get("priority", "medium").strip()

    assignee_id = request.form.get("assignee_id") or None
    assignee_id = int(assignee_id) if assignee_id else None

    # 1) create issue
    issue_id = create_issue(project_id, title, description, priority, int(current_user.id), assignee_id, due_date)

    # 2) optional attachment on create
    f = request.files.get("file")
    if f and f.filename:
        from pathlib import Path
        import uuid
        from werkzeug.utils import secure_filename

        original = secure_filename(f.filename)
        ext = Path(original).suffix.lower()
        stored = f"{uuid.uuid4().hex}{ext}"

        target_dir = _issue_dir(issue_id)
        target_path = target_dir / stored
        f.save(target_path)

        add_issue_file(
            issue_id=issue_id,
            uploader_id=int(current_user.id),
            stored_name=stored,
            original_name=original,
            mime_type=f.mimetype or "",
            size_bytes=target_path.stat().st_size,
        )
        log_issue_event(issue_id, int(current_user.id), "file_uploaded_on_create")

    # 3) email assignee
    if assignee_id:
        assignee = get_user_by_id(assignee_id)
        if assignee and mail_is_configured():
            try:
                send_issue_assigned(
                    to=assignee["email"],
                    assignee_name=assignee["name"],
                    issue_id=issue_id,
                    title=title,
                    priority=priority,
                    issue_url=f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}",
                )
                log_issue_event(issue_id, int(current_user.id), "assigned_email_sent")
            except MailerError as e:
                flash(f"Issue created, email failed: {e}", "error")

    flash("Issue created", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))


@app.get("/issues/<int:issue_id>")
@login_required
def issue_view(issue_id: int):
    issue = get_issue_view(issue_id)
    if not issue:
        abort(404)

    files = list_issue_files(issue_id)
    return render_template(
        "issue_view.html",
        issue=issue,
        comments=list_comments(issue_id),
        files=files,
        mail_enabled=mail_is_configured(),
    )


@app.post("/issues/<int:issue_id>/comment")
@login_required
def issue_add_comment(issue_id: int):
    """
    Add a comment to an issue.
    If the actor is the reporter -> notify assignee (if exists).
    If the actor is the assignee -> notify reporter.
    (All DB interaction is in TrackletDB.)
    """
    body = (request.form.get("body") or "").strip()
    if not body:
        flash("Comment cannot be empty", "error")
        return redirect(url_for("issue_view", issue_id=issue_id))

    # Ensure issue exists + get details for email subject/body
    issue = get_issue_view(issue_id)
    if not issue:
        abort(404)

    # DB: insert comment + audit event
    add_comment(issue_id, int(current_user.id), body)
    log_issue_event(issue_id, int(current_user.id), "comment_added")

    # DB: determine who should be notified (reporter<->assignee)
    recipient = get_issue_notify_recipient(issue_id, int(current_user.id))

    # Mail: notify the other party (if configured)
    if recipient and mail_is_configured():
        try:
            issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"
            send_issue_comment(
                to=recipient["email"],
                recipient_name=recipient["name"],
                issue_id=int(issue["id"]),
                title=issue["title"],
                actor_name=current_user.name,
                comment_text=body,
                issue_url=issue_url,
            )
            log_issue_event(issue_id, int(current_user.id), "comment_email_sent")
        except MailerError as e:
            # Comment is saved even if email fails
            flash(f"Comment saved, email failed: {e}", "error")

    flash("Comment added", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))



@app.post("/issues/<int:issue_id>/close")
@login_required
def issue_close(issue_id: int):
    row = db_read_one("SELECT assignee_id, status FROM issues WHERE id=?", (issue_id,))
    if not row:
        abort(404)

    if row["status"] == "closed":
        return redirect(url_for("issue_view", issue_id=issue_id))

    if row["assignee_id"] != int(current_user.id) and not is_admin():
        abort(403)

    close_issue(issue_id)
    log_issue_event(issue_id, int(current_user.id), "issue_closed")
    flash("Issue closed", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))


@app.post("/issues/<int:issue_id>/remind")
@login_required
def issue_remind(issue_id: int):
    issue = get_issue_compact(issue_id)
    if not issue:
        abort(404)

    if issue["status"] == "closed":
        abort(400, "Issue is closed")
    if not issue["assignee_id"]:
        abort(400, "No assignee")

    assignee = get_user_by_id(issue["assignee_id"])
    if not assignee:
        abort(400, "Assignee not found")
    if int(assignee["id"]) == int(current_user.id):
        abort(400, "You cannot remind yourself")

    if not mail_is_configured():
        flash("Email not configured (SMTP_* env vars missing)", "error")
        return redirect(url_for("issue_view", issue_id=issue_id))

    try:
        send_issue_reminder(
            to=assignee["email"],
            assignee_name=assignee["name"],
            issue_id=issue["id"],
            title=issue["title"],
            project_name=issue["project_name"],
            status=issue["status"],
            priority=issue["priority"],
            sender_name=current_user.name,
            issue_url=f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}",
        )
        log_issue_event(issue_id, int(current_user.id), "reminder_sent")
        flash("Reminder sent", "success")
    except MailerError as e:
        flash(str(e), "error")

    return redirect(url_for("issue_view", issue_id=issue_id))

def _notify_other_party(issue_row, actor_user, message: str, kind: str, new_status: str | None = None):
    """
    kind = "comment" | "status"
    """
    if not mail_is_configured():
        return
    if not issue_row:
        return

    reporter_id = int(issue_row["reporter_id"])
    assignee_id = issue_row["assignee_id"]
    assignee_id = int(assignee_id) if assignee_id is not None else None

    # Determine recipient:
    if actor_user.id == reporter_id:
        # reporter -> assignee
        if not assignee_id:
            return
        recipient = get_user_by_id(assignee_id)
    elif assignee_id and actor_user.id == assignee_id:
        # assignee -> reporter
        recipient = get_user_by_id(reporter_id)
    else:
        # watchers later; for now only reporter/assignee logic
        return

    if not recipient:
        return

    issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_row['id'])}"
    actor_name = actor_user.name

    if kind == "comment":
        send_issue_comment(
            to=recipient["email"],
            recipient_name=recipient["name"],
            issue_id=int(issue_row["id"]),
            title=issue_row["title"],
            actor_name=actor_name,
            comment_text=message,
            issue_url=issue_url,
        )
    elif kind == "status" and new_status:
        send_issue_status_changed(
            to=recipient["email"],
            recipient_name=recipient["name"],
            issue_id=int(issue_row["id"]),
            title=issue_row["title"],
            actor_name=actor_name,
            new_status=new_status,
            note_text=message or "",
            issue_url=issue_url,
        )



@app.post("/issues/<int:issue_id>/status")
@login_required
def issue_set_status(issue_id: int):
    """
    Change issue status (open/closed/in_progress/blocked).
    Optional note: if provided, it is stored as a comment.
    Notify the other party (reporter <-> assignee) when reporter/assignee changes status,
    and include the note if provided.
    """
    new_status = (request.form.get("status") or "").strip()
    note = (request.form.get("note") or "").strip()

    if new_status not in ("open", "closed", "in_progress", "blocked"):
        flash("Invalid status", "error")
        return redirect(url_for("issue_view", issue_id=issue_id))

    # Ensure issue exists (also used for email)
    issue_before = get_issue_view(issue_id)
    if not issue_before:
        abort(404)

    # DB: update status
    set_issue_status(issue_id, new_status)
    log_issue_event(issue_id, int(current_user.id), "status_changed", meta_json=new_status)

    # DB: store note as a comment (optional)
    if note:
        add_comment(issue_id, int(current_user.id), note)
        log_issue_event(issue_id, int(current_user.id), "status_note_added")

    # Notify reporter/assignee counterpart (DB decides recipient)
    recipient = get_issue_notify_recipient(issue_id, int(current_user.id))

    if recipient and mail_is_configured():
        try:
            issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"
            send_issue_status_changed(
                to=recipient["email"],
                recipient_name=recipient["name"],
                issue_id=int(issue_before["id"]),
                title=issue_before["title"],
                actor_name=current_user.name,
                new_status=new_status,
                note_text=note,
                issue_url=issue_url,
            )
            log_issue_event(issue_id, int(current_user.id), "status_email_sent", meta_json=new_status)
        except MailerError as e:
            flash(f"Status updated, email failed: {e}", "error")

    flash("Status updated", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))


# -------------------------------------------------
# Admin
# -------------------------------------------------
@app.get("/admin/projects")
@login_required
def admin_projects():
    if not is_admin():
        abort(403)
    return render_template("admin_projects.html", projects=list_projects_admin())


@app.post("/admin/projects")
@login_required
def admin_projects_post():
    if not is_admin():
        abort(403)

    name = request.form.get("name", "").strip()
    if not name:
        flash("Project name required", "error")
        return redirect(url_for("admin_projects"))

    create_project(name, request.form.get("description", "").strip())
    flash("Project created", "success")
    return redirect(url_for("admin_projects"))


@app.post("/admin/projects/<int:project_id>/github")
@login_required
def admin_project_github(project_id: int):
    if not is_admin():
        abort(403)

    owner = request.form.get("github_owner", "")
    repo = request.form.get("github_repo", "")
    branch = request.form.get("github_default_branch", "main")
    repo_url = request.form.get("github_repo_url", "")

    update_project_github(project_id, owner, repo, branch, repo_url)
    flash("GitHub settings saved", "success")
    return redirect(url_for("admin_projects"))

@app.post("/admin/projects/<int:project_id>/delete")
@login_required
def admin_project_delete(project_id: int):
    if not is_admin():
        abort(403)

    # If project has issues -> soft delete (deactivate)
    if project_has_issues(project_id):
        deactivate_project(project_id)
        flash("Project deactivated (had issues).", "success")
    else:
        delete_project_hard(project_id)
        flash("Project deleted.", "success")

    return redirect(url_for("admin_projects"))

@app.get("/admin/users")
@login_required
def admin_users():
    if not is_admin():
        abort(403)
    return render_template(
        "admin_users.html",
        users=list_users_admin(),
        roles=list_roles_active(),
    )


@app.post("/admin/users")
@login_required
def admin_users_post():
    if not is_admin():
        abort(403)

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "user").strip()
    password = request.form.get("password", "").strip()

    if not name or not email or not password:
        flash("Name, email, password are required", "error")
        return redirect(url_for("admin_users"))

    try:
        create_user(name, email, role, generate_password_hash(password))
        flash("User created", "success")
    except sqlite3.IntegrityError:
        flash("Email already exists", "error")

    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/update")
@login_required
def admin_user_update(user_id: int):
    if not is_admin():
        abort(403)

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "user").strip()
    new_password = request.form.get("password", "").strip()

    if not name or not email:
        flash("Name and email are required", "error")
        return redirect(url_for("admin_users"))

    pwd_hash = generate_password_hash(new_password) if new_password else None
    update_user(user_id, name, email, role, pwd_hash)

    flash("User updated", "success")
    return redirect(url_for("admin_users"))

# -------------------------------------------------
# Roles
# -------------------------------------------------

@app.get("/admin/roles")
@login_required
def admin_roles_list():
    if not is_admin():
        abort(403)
    roles = list_roles_admin()
    return {"roles": [dict(r) for r in roles]}


@app.post("/admin/roles/add")
@login_required
def admin_roles_add():
    if not is_admin():
        abort(403)

    name = (request.form.get("name") or "").strip()
    if not name:
        return {"ok": False, "error": "Role name required"}, 400

    # prevent duplicates like ADMIN vs admin if you want:
    name = name.lower()

    try:
        add_role(name)
        return {"ok": True}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "Role already exists"}, 400


@app.post("/admin/roles/delete")
@login_required
def admin_roles_delete():
    if not is_admin():
        abort(403)

    name = (request.form.get("name") or "").strip().lower()
    if not name:
        return {"ok": False, "error": "Role name required"}, 400

    if name in ("admin", "user"):
        return {"ok": False, "error": "Cannot delete core role"}, 400

    if role_in_use(name):
        return {"ok": False, "error": "Role is in use by users"}, 400

    delete_role(name)
    return {"ok": True}

@app.get("/settings")
@login_required
def my_settings():
    return render_template("my_settings.html", me=get_user_by_id(int(current_user.id)))


@app.post("/settings")
@login_required
def my_settings_post():
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    pwd = (request.form.get("password") or "").strip()

    if not name or not email:
        flash("Name and email are required", "error")
        return redirect(url_for("my_settings"))

    # if email belongs to someone else -> block
    other = get_user_by_email(email)
    if other and int(other["id"]) != int(current_user.id):
        flash("Email already used by another user", "error")
        return redirect(url_for("my_settings"))

    pwd_hash = generate_password_hash(pwd) if pwd else None
    update_my_settings(int(current_user.id), name, email, pwd_hash)

    flash("Settings updated", "success")
    return redirect(url_for("my_settings"))
# -------------------------------------------------
# Health (optional)
# -------------------------------------------------
@app.get("/health")
def health():
    return {
        "ok": True,
        "app": settings.APP_NAME,
        "db_path": settings.DB_PATH,
        "upload_dir": settings.UPLOAD_DIR,
        "mail_configured": mail_is_configured(),
    }


if __name__ == "__main__":
    app.run(debug=True)
