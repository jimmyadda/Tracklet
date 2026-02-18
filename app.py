# app.py
from datetime import date, timedelta
from pathlib import Path
import secrets
import shutil
import sqlite3
import uuid

from flask import Flask, jsonify, render_template, request, redirect, send_from_directory, url_for, flash, abort,send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from flask import send_from_directory
from werkzeug.utils import secure_filename,safe_join
import mimetypes
from config import settings
from TrackletDB import (
    add_comment_file, add_issue_file, add_role, deactivate_project, delete_issue_file, delete_project_hard, delete_role, delete_user_cascade, ensure_default_roles, get_comment_file, get_issue_file, get_issue_notify_recipient, get_my_reported_issues, get_my_tasks_history, get_project_name, init_db, bootstrap_if_empty,

    # users
    get_user_by_id, get_user_by_email, list_comment_files_for_issue, list_issue_files,  list_roles_active, list_roles_admin,
    list_users_active, list_users_admin, create_user,

    # projects
    list_projects_active, list_projects_admin, create_project,
    get_project, list_project_issues, migrate_db, project_has_issues, role_in_use, search_issues, search_projects, set_issue_assignee, set_issue_status, set_issue_watcher, update_my_settings, update_project_github,

    # issues
    get_my_tasks, create_issue, get_issue_view, get_issue_compact, close_issue,

    # comments
    list_comments, add_comment,

    # events
    log_issue_event,

    # generic (small permission check query)
    db_read_one, update_user, update_user_info,
)

from TrackletMailer import (
    send_issue_assigned,
    send_issue_comment,
    send_issue_created_watcher,
    send_issue_reminder,
    MailerError,
    is_configured as mail_is_configured,
    send_issue_status_changed,
    send_issue_status_watcher,
    send_welcome_user,
)

from TrackletGitHub import get_releases, get_tags
from werkzeug.middleware.proxy_fix import ProxyFix


# -------------------------------------------------
# App setup
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = settings.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


app.config.update(
    # ---- Session cookie (MAIN login cookie) ----
    SESSION_COOKIE_SECURE=True,        # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,      # Not accessible via JS
    SESSION_COOKIE_SAMESITE="Lax",     # Safe default

    # ---- Remember-me cookie (Flask-Login) ----
    REMEMBER_COOKIE_DURATION=timedelta(days=14),
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
)

app.config["REMEMBER_COOKIE_SECURE"] = not app.debug

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@app.context_processor
def inject_settings():
    return {"settings": settings}
# -------------------------------------------------
# User model
# -------------------------------------------------

import os
import shutil

db_path = os.environ.get("DB_PATH", "data/tracklet.sqlite3")
seed_path = "data/seed_tracklet.sqlite3"

if db_path.startswith("/data/") and not os.path.exists(db_path) and os.path.exists(seed_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    shutil.copy2(seed_path, db_path)
    print(f"✅ Seeded DB to {db_path}", flush=True)


    
class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.email = row["email"]
        self.name = row["name"]
        self.role = row["role"]
        self.photo_path = row["photo_path"]
        self._is_active = bool(row["is_active"])   #  IMPORTANT

    @property
    def is_active(self):
        return self._is_active


@login_manager.user_loader
def load_user(user_id: str):
    row = get_user_by_id(int(user_id))
    return User(row) if row else None


def is_admin() -> bool:
    return current_user.is_authenticated and current_user.role == "admin"


@app.context_processor
def inject_helpers():
    def due_class(due_date_str, status):
        if not due_date_str or status == "closed":
            return ""
        try:
            y, m, d = map(int, str(due_date_str)[:10].split("-"))
            due = date(y, m, d)
        except Exception:
            return ""
        today = date.today()
        if due < today:
            return "row-overdue"       # red
        if due == today:
            return "row-due-today"     # yellow
        return ""
    return {"due_class": due_class}

# -------------------------------------------------
# Helpers
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

def _move_temp_attachments_to_issue(issue_id: int, uploader_id: int):
    temp_stored = request.form.getlist("temp_stored[]")
    temp_original = request.form.getlist("temp_original[]")
    temp_mime = request.form.getlist("temp_mime[]")
    temp_size = request.form.getlist("temp_size[]")

    if not temp_stored:
        return

    tdir = _temp_dir()
    idir = _issue_dir(issue_id)

    # safety: ensure parallel arrays
    n = min(len(temp_stored), len(temp_original), len(temp_mime), len(temp_size))

    for i in range(n):
        stored = temp_stored[i]
        original = temp_original[i] or stored
        mime = (temp_mime[i] or "").strip()
        try:
            size_bytes = int(temp_size[i] or 0)
        except ValueError:
            size_bytes = 0

        src = tdir / stored
        if not src.exists():
            continue

        # move temp -> issue folder
        dst = idir / stored
        shutil.move(str(src), str(dst))

        # if size missing, compute now
        if size_bytes <= 0 and dst.exists():
            size_bytes = dst.stat().st_size

        # insert DB record (uses your existing function)
        add_issue_file(
            issue_id=issue_id,
            uploader_id=int(uploader_id),
            stored_name=stored,
            original_name=original,
            mime_type=mime,
            size_bytes=size_bytes,
        )

def _temp_dir() -> Path:
    base = _ensure_upload_dir()
    d = base / "temp"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _comment_dir(issue_id: int, comment_id: int) -> Path:
    d = _issue_dir(issue_id) / "comments" / f"comment_{comment_id}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _temp_comment_dir(issue_id: int) -> Path:
    d = _issue_dir(issue_id) / "temp_comments"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _finalize_comment_temp_files(issue_id: int, comment_id: int, uploader_id: int):
    temp_stored = request.form.getlist("temp_stored[]")
    temp_original = request.form.getlist("temp_original[]")
    temp_mime = request.form.getlist("temp_mime[]")
    temp_size = request.form.getlist("temp_size[]")

    if not temp_stored:
        return

    tdir = _temp_comment_dir(issue_id)
    dest = _comment_dir(issue_id, comment_id)

    n = min(len(temp_stored), len(temp_original), len(temp_mime), len(temp_size))
    for i in range(n):
        stored = (temp_stored[i] or "").strip()
        if not stored:
            continue

        src = tdir / stored
        if not src.exists():
            continue

        original = (temp_original[i] or stored).strip()
        mime = (temp_mime[i] or "").strip()
        try:
            size_bytes = int(temp_size[i] or 0)
        except ValueError:
            size_bytes = 0

        dst = dest / stored
        shutil.move(str(src), str(dst))

        if size_bytes <= 0 and dst.exists():
            size_bytes = dst.stat().st_size

        add_comment_file(
            comment_id=comment_id,
            uploader_id=uploader_id,
            stored_name=stored,
            original_name=original,
            mime_type=mime,
            size_bytes=size_bytes,
        )

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
    remember = request.form.get("remember") == "1"

    row = get_user_by_email(email)
    if not row or not check_password_hash(row["password_hash"], password):
        flash("Invalid email or password", "error")
        return redirect(url_for("login"))

    # ✅ block inactive users (important for remember-me + security)
    if not int(row["is_active"]):
        flash("Your account is inactive. Contact admin.", "error")
        return redirect(url_for("login"))

    login_user(User(row), remember=remember)
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
    issues = get_my_tasks(int(current_user.id), include_closed=False)
    return render_template("my_tasks.html", issues=issues)

@app.get("/my-tasks/history")
@login_required
def my_tasks_history():
    issues = get_my_tasks_history(int(current_user.id))
    return render_template("my_tasks_history.html", issues=issues)
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


@app.post("/issues/upload-temp")
@login_required
def issue_upload_temp():
    f = request.files.get("file")
    if not f:
        abort(400)

    original = secure_filename(f.filename or "")
    # if paste comes without name, make one:
    if not original:
        original = f"pasted_{uuid.uuid4().hex}.png"

    ext = Path(original).suffix.lower()
    stored = f"{uuid.uuid4().hex}{ext}"

    target = _temp_dir() / stored
    f.save(target)

    size_bytes = target.stat().st_size
    mime_type = (f.mimetype or "").strip()
    if not mime_type:
        mime_type = mimetypes.guess_type(original)[0] or "application/octet-stream"

    return jsonify({
        "stored_name": stored,
        "original_name": original,
        "mime_type": mime_type,
        "size_bytes": size_bytes,
    })


@app.get("/files/<int:file_id>/download")
@login_required
def file_download(file_id: int):
    row = get_issue_file(file_id)
    if not row:
        abort(404)

    issue_id = int(row["issue_id"])
    directory = _issue_dir(issue_id)

    stored_name = row["stored_name"]
    original_name = row["original_name"] or stored_name

    full_path = Path(directory) / stored_name
    if not full_path.exists():
        abort(404)

    mime = (row["mime_type"] or "").strip()
    if not mime:
        mime = mimetypes.guess_type(original_name)[0] or "application/octet-stream"

    return send_file(
        full_path,
        mimetype=mime,
        as_attachment=True,
        download_name=original_name,
        conditional=True,
    )


@app.get("/files/<int:file_id>/view")
@login_required
def file_view(file_id: int):
    row = get_issue_file(file_id)
    if not row:
        abort(404)

    issue_id = int(row["issue_id"])
    full_path = _issue_dir(issue_id) / row["stored_name"]
    if not full_path.exists():
        abort(404)

    mime = (row["mime_type"] or "").strip() or mimetypes.guess_type(row["original_name"])[0] or "application/octet-stream"
    return send_file(full_path, mimetype=mime, as_attachment=False, conditional=True)


@app.post("/files/<int:file_id>/delete")
@login_required
def file_delete(file_id: int):
    row = get_issue_file(file_id)
    if not row:
        abort(404)

    issue_id = int(row["issue_id"])
    stored_name = row["stored_name"]

    # (Optional but recommended) authorize: only uploader or issue owner/admin can delete
    # if int(row["uploader_id"]) != int(current_user.id) and not current_user.is_admin:
    #     abort(403)

    # Delete file from disk
    full_path = _issue_dir(issue_id) / stored_name
    try:
        if full_path.exists():
            full_path.unlink()
    except Exception as e:
        # don't fail hard; still remove DB record if you want
        flash(f"Could not delete file from disk: {e}", "error")

    # Delete record from DB
    delete_issue_file(file_id)  # <-- you implement this
    log_issue_event(issue_id, int(current_user.id), "file_deleted")

    flash("File deleted", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))

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
    watcher_raw = (request.form.get("watcher_id") or "").strip()
    watcher_id = int(watcher_raw) if watcher_raw.isdigit() else None

    # 1) create issue
    issue_id = create_issue(project_id, title, description, priority, int(current_user.id), assignee_id, due_date)
    if watcher_id:
        set_issue_watcher(issue_id, watcher_id)
        log_issue_event(issue_id, int(current_user.id), "watcher_set_on_create")
    
    # ✅ NEW: move any temp/pasted attachments into this new issue
    _move_temp_attachments_to_issue(issue_id, int(current_user.id))
    # optional: log if any were moved (only if you want)
    if request.form.getlist("temp_stored[]"):
        log_issue_event(issue_id, int(current_user.id), "file_uploaded_on_create")    
    
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
                issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"
                send_issue_assigned(
                    to=assignee["email"],
                    recipient_name=assignee["name"],
                    issue_id=issue_id,
                    title=title,
                    project_name=get_project_name(project_id),  # or issue["project_name"] if you have it
                    assigner_name=current_user.name,
                    issue_url=issue_url,
                )
                log_issue_event(issue_id, int(current_user.id), "assigned_email_sent")
            except MailerError as e:
                flash(f"Issue created, email failed: {e}", "error")
    _notify_single_watcher_created(issue_id)

    flash("Issue created", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))


@app.get("/issues/<int:issue_id>")
@login_required
def issue_view(issue_id: int):
    issue = get_issue_view(issue_id)
    users = list_users_active()
    comments = list_comments(issue_id)
    files = list_comment_files_for_issue(issue_id)

    by_comment = {}
    for f in files:
        by_comment.setdefault(int(f["comment_id"]), []).append(f)

    # attach list to each comment
    comments_out = []
    for c in comments:
        d = dict(c)
        d["files"] = by_comment.get(int(c["id"]), [])
        comments_out.append(d)    

    if not issue:
        abort(404)

    files = list_issue_files(issue_id)
    return render_template(
        "issue_view.html",
        issue=issue,
        comments=comments_out,
        users=users,
        files=files,
        mail_enabled=mail_is_configured(),
    )


@app.post("/issues/<int:issue_id>/close")
@login_required
def issue_close(issue_id: int):
    issue = get_issue_view(issue_id)
    if not issue:
        abort(404)

    if issue["status"] == "closed":
        return redirect(url_for("issue_view", issue_id=issue_id))

    actor_id = int(current_user.id)
    reporter_id = int(issue["reporter_id"])
    assignee_id = int(issue["assignee_id"]) if issue["assignee_id"] is not None else None

    # Permission: assignee OR reporter OR admin
    if (actor_id not in (reporter_id, assignee_id)) and not is_admin():
        abort(403)

    # 1) DB close
    set_issue_status(issue_id, "closed")
    log_issue_event(issue_id, actor_id, "issue_closed")

    issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"

    # Helper to email one user about status change (no notes)
    def _email_status(user_id: int):
        u = get_user_by_id(user_id)
        if not u or not mail_is_configured():
            return
        try:
            send_issue_status_changed(
                to=u["email"],
                recipient_name=u["name"],
                issue_id=int(issue["id"]),
                title=issue["title"],
                actor_name=current_user.name,
                new_status="closed",
                note_text="",  # NO notes here
                issue_url=issue_url,
            )
            log_issue_event(issue_id, actor_id, "status_email_sent", meta_json=f"closed_to_{user_id}")
        except MailerError as e:
            flash(f"Issue closed, email failed: {e}", "error")

    # 2) Who to notify?
    # - If assignee closes -> notify reporter (+ watcher)
    # - If reporter closes -> notify assignee (+ watcher)
    # - If admin/other allowed -> notify both reporter+assignee except actor
    if mail_is_configured():
        if actor_id == assignee_id:
            # assignee closes
            if reporter_id != actor_id:
                _email_status(reporter_id)
        elif actor_id == reporter_id:
            # reporter closes
            if assignee_id and assignee_id != actor_id:
                _email_status(assignee_id)
        else:
            # admin closes (or other allowed)
            if reporter_id != actor_id:
                _email_status(reporter_id)
            if assignee_id and assignee_id != actor_id:
                _email_status(assignee_id)

    # 3) Watcher always gets status email (no notes)
    _notify_single_watcher_status(issue_id, "closed")

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


@app.post("/issues/<int:issue_id>/assignee")
@login_required
def issue_set_assignee(issue_id: int):
    issue = get_issue_view(issue_id)
    if not issue:
        abort(404)

    old_assignee_id = int(issue["assignee_id"]) if issue["assignee_id"] is not None else None

    assignee_raw = (request.form.get("assignee_id") or "").strip()
    new_assignee_id = int(assignee_raw) if assignee_raw.isdigit() else None

    # If no change, do nothing
    if old_assignee_id == new_assignee_id:
        flash("Assignee unchanged", "info")
        return redirect(url_for("issue_view", issue_id=issue_id))

    # DB update
    set_issue_assignee(issue_id, new_assignee_id)
    log_issue_event(issue_id, int(current_user.id), "assignee_changed")

    # Notify new assignee
    if new_assignee_id and mail_is_configured():
        assignee = get_user_by_id(new_assignee_id)
        if assignee:
            try:
                issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"
                send_issue_assigned(
                    to=assignee["email"],
                    recipient_name=assignee["name"],
                    issue_id=int(issue["id"]),
                    title=issue["title"],
                    project_name=issue["project_name"],
                    assigner_name=current_user.name,
                    issue_url=issue_url,
                )
                log_issue_event(issue_id, int(current_user.id), "assigned_email_sent")
            except MailerError as e:
                flash(f"Assignee updated, email failed: {e}", "error")

    flash("Assignee updated", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))

@app.get("/my-reported")
@login_required
def my_reported():
    issues = get_my_reported_issues(int(current_user.id), include_closed=True)
    return render_template("my_reported.html", issues=issues)

# -------------------------------------------------
# comments
# -------------------------------------------------

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


@app.post("/issues/<int:issue_id>/comments/upload-temp")
@login_required
def comment_upload_temp(issue_id: int):
    issue = get_issue_view(issue_id)
    if not issue:
        abort(404)

    f = request.files.get("file")
    if not f:
        abort(400)

    original = secure_filename(f.filename or "") or f"pasted_{uuid.uuid4().hex}.png"
    ext = Path(original).suffix.lower()
    stored = f"{uuid.uuid4().hex}{ext}"

    tdir = _temp_comment_dir(issue_id)
    path = tdir / stored
    f.save(path)

    mime_type = (f.mimetype or "").strip()
    if not mime_type:
        mime_type = mimetypes.guess_type(original)[0] or "application/octet-stream"

    return jsonify({
        "stored_name": stored,
        "original_name": original,
        "mime_type": mime_type,
        "size_bytes": path.stat().st_size,
    })

@app.post("/issues/<int:issue_id>/comments")
@login_required
def comment_add_post(issue_id: int):
    body = (request.form.get("body") or "").strip()

    temp_stored = request.form.getlist("temp_stored[]")
    if not body and not temp_stored:
        flash("Comment is empty", "error")
        return redirect(url_for("issue_view", issue_id=issue_id))
    

    issue = get_issue_view(issue_id)
    # 1) create comment
    comment_id = add_comment(issue_id, int(current_user.id), body)
    log_issue_event(issue_id, int(current_user.id), "comment_added")
    # 2) finalize temp attachments
    _finalize_comment_temp_files(issue_id, comment_id, int(current_user.id))
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


    log_issue_event(issue_id, int(current_user.id), "comment_added")
    flash("Comment added", "success")
    return redirect(url_for("issue_view", issue_id=issue_id) + "#comments")


@app.get("/comment-files/<int:file_id>/view")
@login_required
def comment_file_view(file_id: int):
    row = get_comment_file(file_id)
    if not row:
        abort(404)

    issue_id = int(row["issue_id"])
    comment_id = int(row["comment_id"])
    full_path = _comment_dir(issue_id, comment_id) / row["stored_name"]
    if not full_path.exists():
        abort(404)

    mime = (row["mime_type"] or "").strip()
    if not mime:
        mime = mimetypes.guess_type(row["original_name"] or row["stored_name"])[0] or "application/octet-stream"

    return send_file(full_path, mimetype=mime, as_attachment=False, conditional=True)

@app.get("/comment-files/<int:file_id>/download")
@login_required
def comment_file_download(file_id: int):
    row = get_comment_file(file_id)
    if not row:
        abort(404)

    issue_id = int(row["issue_id"])
    comment_id = int(row["comment_id"])
    full_path = _comment_dir(issue_id, comment_id) / row["stored_name"]
    if not full_path.exists():
        abort(404)

    mime = (row["mime_type"] or "").strip() or "application/octet-stream"
    return send_file(full_path, mimetype=mime, as_attachment=True,
                     download_name=row["original_name"] or row["stored_name"],
                     conditional=True)

# -------------------------------------------------
# Watcher
# -------------------------------------------------

@app.post("/issues/<int:issue_id>/watcher")
@login_required
def issue_set_watcher(issue_id: int):
    watcher_raw = (request.form.get("watcher_id") or "").strip()
    watcher_id = int(watcher_raw) if watcher_raw.isdigit() else None

    set_issue_watcher(issue_id, watcher_id)
    log_issue_event(issue_id, int(current_user.id), "watcher_changed")
    flash("Watcher updated", "success")
    return redirect(url_for("issue_view", issue_id=issue_id))



def _notify_single_watcher_created(issue_id: int):
    if not mail_is_configured():
        return

    issue = get_issue_view(issue_id)
    if not issue or not issue["watcher_id"]:
        return

    watcher = get_user_by_id(int(issue["watcher_id"]))
    if not watcher:
        return

    exclude_ids = {int(current_user.id), int(issue["reporter_id"])}
    if issue["assignee_id"] is not None:
        exclude_ids.add(int(issue["assignee_id"]))

    if int(watcher["id"]) in exclude_ids:
        return

    issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"
    try:
        send_issue_created_watcher(
            to=watcher["email"],
            watcher_name=watcher["name"],
            issue_id=int(issue["id"]),
            title=issue["title"],
            project_name=issue["project_name"],
            creator_name=current_user.name,
            issue_url=issue_url,
        )
    except MailerError:
        pass


def _notify_single_watcher_status(issue_id: int, new_status: str):
    if not mail_is_configured():
        return

    issue = get_issue_view(issue_id)
    if not issue or not issue["watcher_id"]:
        return

    watcher = get_user_by_id(int(issue["watcher_id"]))
    if not watcher:
        return

    exclude_ids = {int(current_user.id), int(issue["reporter_id"])}
    if issue["assignee_id"] is not None:
        exclude_ids.add(int(issue["assignee_id"]))

    if int(watcher["id"]) in exclude_ids:
        return

    issue_url = f"{request.url_root.rstrip('/')}{url_for('issue_view', issue_id=issue_id)}"
    try:
        send_issue_status_watcher(
            to=watcher["email"],
            watcher_name=watcher["name"],
            issue_id=int(issue["id"]),
            title=issue["title"],
            project_name=issue["project_name"],
            actor_name=current_user.name,
            new_status=new_status,
            issue_url=issue_url,
        )
    except MailerError:
        pass



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
        # Create user returns lastrowid
        user_id = create_user(name, email, role, generate_password_hash(password))
        flash("User created", "success")

        # Send welcome email 
        if mail_is_configured():
            try:
                # Adjust endpoint name if yours is different (e.g. login_get)
                login_url = f"{request.url_root.rstrip('/')}{url_for('login')}"
                send_welcome_user(
                    to=email,
                    name=name,
                    temp_password=password,
                    login_url=login_url,
                )
                # optional: if you have an admin audit table later; otherwise remove
                # log_admin_event(int(current_user.id), "user_welcome_sent", meta_json=str(user_id))
            except MailerError as e:
                flash(f"User created, email failed: {e}", "error")

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

@app.post("/admin/users/<int:user_id>/delete")
@login_required
def admin_user_delete(user_id: int):
    if not is_admin():
        abort(403)

    if int(current_user.id) == int(user_id):
        flash("You cannot delete yourself.", "error")
        return redirect(url_for("admin_users"))

    delete_user_cascade(user_id=user_id, fallback_reporter_id=int(current_user.id))
    flash("User deleted.", "success")
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
    return render_template(
        "my_settings.html",
        me=get_user_by_id(int(current_user.id)),
        roles=list_roles_active(),
    )


@app.post("/settings")
@login_required
def my_settings_post():
    name = (request.form.get("name") or "").strip()
    role = (request.form.get("role") or "").strip()
    pwd = (request.form.get("password") or "").strip()

    if not name or not role:
        flash("Name and role are required", "error")
        return redirect(url_for("my_settings"))

    pwd_hash = generate_password_hash(pwd) if pwd else None
    update_my_settings(int(current_user.id), name, role, pwd_hash)

    flash("Settings updated", "success")
    return redirect(url_for("my_settings"))

@app.post("/admin/users/<int:user_id>/welcome")
@login_required
def admin_send_welcome(user_id: int):
    if not is_admin():
        abort(403)

    user = get_user_by_id(user_id)
    if not user:
        abort(404)

    temp_password = secrets.token_urlsafe(8)
    pwd_hash = generate_password_hash(temp_password)

    update_user_info(
        user_id=user_id,
        name=user["name"] or "User",
        email=user["email"],
        role=user["role"],
        password_hash=pwd_hash,
    )

    if not mail_is_configured():
        flash("User updated, but mail is not configured", "warning")
        return redirect(url_for("admin_users"))

    login_url = f"{request.url_root.rstrip('/')}{url_for('login')}"
    try:
        send_welcome_user(
            to=user["email"],
            name=user["name"] or "User",
            temp_password=temp_password,
            login_url=login_url,
        )
        flash("User updated and welcome email sent ✅", "success")
    except Exception as e:
        flash(f"User updated but email failed: {e}", "danger")

    return redirect(url_for("admin_users"))

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

@app.get("/admin/mail-debug")
@login_required
def admin_mail_debug():
    if not is_admin():
        abort(403)
    return {
        "MAIL_PROVIDER": settings.MAIL_PROVIDER,
        "RESEND_KEY_SET": bool(settings.RESEND_API_KEY),
        "SMTP_FROM": settings.SMTP_FROM,
        "MAIL_CONFIGURED": mail_is_configured(),
    }

@app.get("/admin/env-debug")
@login_required
def admin_env_debug():
    if not is_admin():
        abort(403)

    keys = ["MAIL_PROVIDER", "RESEND_API_KEY", "SMTP_FROM", "BASE_URL", "DB_PATH"]
    return {k: ("<set>" if os.getenv(k) else None) if k == "RESEND_API_KEY" else os.getenv(k) for k in keys}


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)