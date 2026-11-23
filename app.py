import os, secrets
from functools import wraps
from urllib.parse import urlencode
import requests
import psycopg
from cryptography.fernet import Fernet
from flask import Flask, request, redirect, session, abort, render_template_string, url_for

app = Flask(__name__)
app.secret_key = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=500000)
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
BASE = os.getenv("BASE_URL", "").rstrip("/")
ADMIN = os.getenv("ADMIN_EMAIL", "").strip().lower()
BLOG = os.getenv("BLOG_URL", "https://wpplugininsights.blogspot.com/").rstrip("/") + "/"
DB = os.getenv("DATABASE_URL", "")
KEY = os.getenv("FERNET_KEY", "")
API = "https://www.googleapis.com/blogger/v3"
SCOPE = "https://www.googleapis.com/auth/blogger https://www.googleapis.com/auth/userinfo.email"
CIPHER = Fernet(KEY.encode()) if KEY else None

def configured():
    return all((CLIENT_ID, CLIENT_SECRET, BASE.startswith("https://"), ADMIN, DB, CIPHER, os.getenv("SESSION_SECRET")))

def connection():
    return psycopg.connect(DB)

def initialize():
    with connection() as c:
        c.execute("CREATE TABLE IF NOT EXISTS oauth_account (email TEXT PRIMARY KEY, refresh_token BYTEA NOT NULL, blog_id TEXT NOT NULL)")

def record():
    with connection() as c:
        return c.execute("SELECT refresh_token,blog_id FROM oauth_account WHERE email=%s", (ADMIN,)).fetchone()

def access_token():
    saved = record()
    if not saved:
        raise RuntimeError("Connect the Blogger account first")
    refresh = CIPHER.decrypt(bytes(saved[0])).decode()
    r = requests.post("https://oauth2.googleapis.com/token", data={
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "refresh_token": refresh, "grant_type": "refresh_token"
    }, timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]

def blogger(method, path, **kwargs):
    r = requests.request(method, API + path,
        headers={"Authorization": "Bearer " + access_token()}, timeout=25, **kwargs)
    if not r.ok:
        raise RuntimeError("Blogger request failed: HTTP " + str(r.status_code))
    return r.json() if r.content else {}

def admin_only(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not configured() or session.get("email") != ADMIN:
            return redirect("/")
        return fn(*args, **kwargs)
    return wrapper

def verify_csrf():
    if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
        abort(403)

BASE_HTML = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Plugin Insights – Blogger Bridge</title>
<style>body{background:#f5f7fb;color:#1b293a;font:16px system-ui;margin:0}
main{max-width:800px;margin:40px auto;padding:20px}
section{background:#fff;border:1px solid #dae2ed;border-radius:14px;padding:24px;margin:16px 0}
a{color:#1453b7}button,.btn{background:#1453b7;color:white;text-decoration:none;border:0;border-radius:8px;padding:11px 16px;cursor:pointer}
input,textarea{box-sizing:border-box;display:block;width:100%;padding:12px;margin:8px 0 18px;border:1px solid #b6c1d1;border-radius:8px}
textarea{min-height:260px}</style><main><h1>Blogger Bridge</h1>
<p>Independent editorial dashboard for {{ blog }}</p>{{ content|safe }}</main></html>"""

def page(html, **data):
    return render_template_string(BASE_HTML,
        content=render_template_string(html, **data), blog=BLOG)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def index():
    if not configured():
        missing = [name for name, value in (("GOOGLE_CLIENT_ID", CLIENT_ID), ("GOOGLE_CLIENT_SECRET", CLIENT_SECRET), ("BASE_URL", BASE if BASE.startswith("https://") else ""), ("ADMIN_EMAIL", ADMIN), ("DATABASE_URL", DB), ("FERNET_KEY", KEY if CIPHER else ""), ("SESSION_SECRET", os.getenv("SESSION_SECRET", ""))) if not value]
        return page("<section><h2>Setup required</h2><p>Missing environment variables:</p><ul>{% for name in missing %}<li><code>{{name}}</code></li>{% endfor %}</ul><p>Add these in Render Environment. No secret values are displayed.</p></section>", missing=missing)
    if session.get("email") != ADMIN:
        return page('<section><p>Only the authorized Google account can manage this blog.</p><a class="btn" href="/login">Connect Google</a></section>')
    if not session.get("csrf"):
        session["csrf"] = secrets.token_urlsafe(32)
    try:
        saved = record()
        posts = blogger("GET", f"/blogs/{saved[1]}/posts",
            params={"status": ["draft", "live"], "maxResults": 30}).get("items", []) if saved else []
    except Exception:
        return page("<section><p>Could not load Blogger posts. Check authorization or service logs.</p></section>"), 502
    return page("""<section><p>Connected: {{ email }} · <a href="/logout">Log out</a></p>
    <a class="btn" href="/new">Create draft</a></section><section><h2>Recent posts</h2>
    {% for p in posts %}<p><b>{{p.title}}</b> — {{p.status}}
    {% if p.status == "DRAFT" %}<a href="/edit/{{p.id}}">Edit</a>{% endif %}
    {% if p.url %}<a href="{{p.url}}" target="_blank" rel="noopener">View</a>{% endif %}</p>
    {% else %}<p>No posts found.</p>{% endfor %}</section>""", posts=posts, email=ADMIN)

@app.get("/login")
def login():
    if not configured():
        abort(503)
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = urlencode({
        "client_id": CLIENT_ID, "redirect_uri": BASE + "/oauth/callback",
        "response_type": "code", "scope": SCOPE, "state": state,
        "access_type": "offline", "prompt": "consent"
    })
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params)

@app.get("/oauth/callback")
def callback():
    expected = session.pop("oauth_state", None)
    if not expected or not secrets.compare_digest(expected, request.args.get("state", "")):
        abort(403)
    code = request.args.get("code")
    if not code:
        abort(400)
    r = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "redirect_uri": BASE + "/oauth/callback", "grant_type": "authorization_code"
    }, timeout=20)
    r.raise_for_status()
    t = r.json()
    profile = requests.get("https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": "Bearer " + t["access_token"]}, timeout=20)
    profile.raise_for_status()
    u = profile.json()
    if u.get("email", "").lower() != ADMIN or not u.get("email_verified"):
        abort(403)
    if not t.get("refresh_token"):
        return "Google did not grant an offline token. Revoke this app's access and reconnect.", 400
    b = requests.get(API + "/blogs/byurl", params={"url": BLOG},
        headers={"Authorization": "Bearer " + t["access_token"]}, timeout=20)
    b.raise_for_status()
    initialize()
    with connection() as c:
        c.execute("""INSERT INTO oauth_account(email,refresh_token,blog_id) VALUES(%s,%s,%s)
        ON CONFLICT(email) DO UPDATE SET refresh_token=EXCLUDED.refresh_token, blog_id=EXCLUDED.blog_id""",
        (ADMIN, CIPHER.encrypt(t["refresh_token"].encode()), b.json()["id"]))
    session.clear()
    session["email"] = ADMIN
    session["csrf"] = secrets.token_urlsafe(32)
    return redirect("/")

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")

def editor(post):
    return page("""<section><a href="/">Dashboard</a><h2>{{"Edit draft" if p.id else "New draft"}}</h2>
    <form method="post" action="/save">
    <input type="hidden" name="csrf" value="{{csrf}}">
    <input type="hidden" name="id" value="{{p.id or ''}}">
    <label>Title<input name="title" required maxlength="180" value="{{p.title or ''}}"></label>
    <label>HTML content<textarea name="content" required>{{p.content or ''}}</textarea></label>
    <label>Labels, separated by commas<input name="labels" value="{{labels}}"></label>
    <button type="submit">Save draft</button></form>
    {% if p.id and p.status == "DRAFT" %}
    <form method="post" action="/publish/{{p.id}}">
    <input type="hidden" name="csrf" value="{{csrf}}">
    <button type="submit">Publish draft</button></form>{% endif %}</section>""",
    p=post, csrf=session["csrf"], labels=", ".join(post.get("labels", [])))

@app.get("/new")
@admin_only
def new():
    return editor({})

@app.get("/edit/<post_id>")
@admin_only
def edit(post_id):
    if not post_id.isdigit():
        abort(400)
    saved = record()
    post = blogger("GET", f"/blogs/{saved[1]}/posts/{post_id}")
    if post.get("status") != "DRAFT":
        abort(403)
    return editor(post)

@app.post("/save")
@admin_only
def save():
    verify_csrf()
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    post_id = request.form.get("id", "")
    if not title or not content or len(content) > 200000:
        abort(400)
    payload = {"title": title, "content": content,
      "labels": [s.strip() for s in request.form.get("labels", "").split(",") if s.strip()][:10]}
    saved = record()
    if post_id:
        if not post_id.isdigit():
            abort(400)
        old = blogger("GET", f"/blogs/{saved[1]}/posts/{post_id}")
        if old.get("status") != "DRAFT":
            abort(403)
        blogger("PATCH", f"/blogs/{saved[1]}/posts/{post_id}", json=payload)
    else:
        blogger("POST", f"/blogs/{saved[1]}/posts", params={"isDraft": "true"}, json=payload)
    return redirect("/")

@app.post("/publish/<post_id>")
@admin_only
def publish(post_id):
    verify_csrf()
    if not post_id.isdigit():
        abort(400)
    saved = record()
    old = blogger("GET", f"/blogs/{saved[1]}/posts/{post_id}")
    if old.get("status") != "DRAFT":
        abort(403)
    blogger("POST", f"/blogs/{saved[1]}/posts/{post_id}/publish")
    return redirect("/")
