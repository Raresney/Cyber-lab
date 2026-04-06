"""
Vulnerable Flask Application - FOR TESTING ONLY
This app is intentionally vulnerable. Never deploy to production.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string, redirect, url_for, make_response

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "testlab.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            post_id INTEGER,
            name TEXT,
            comment TEXT
        );
    """)
    # Insert sample data if empty
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executescript("""
            INSERT INTO users (username, password, email, role) VALUES
                ('admin', 'admin123', 'admin@example.com', 'admin'),
                ('john', 'password', 'john@example.com', 'user'),
                ('alice', 'alice2024', 'alice@example.com', 'user');
            INSERT INTO posts (title, content, author) VALUES
                ('Welcome', 'Welcome to our blog!', 'admin'),
                ('Security Tips', 'Always use parameterized queries...', 'john'),
                ('Hello World', 'My first post here', 'alice');
        """)
    conn.commit()
    conn.close()


# ==================== HTML Templates ====================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TestLab - Vulnerable App</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px;
               background: #1a1a2e; color: #e0e0e0; }
        a { color: #00d2ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        nav { background: #16213e; padding: 12px 20px; border-radius: 8px; margin-bottom: 24px; }
        nav a { margin-right: 16px; }
        .card { background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 16px;
                border: 1px solid #2a2a4a; }
        input, textarea { background: #0a0a1a; color: #e0e0e0; border: 1px solid #2a2a4a;
                          padding: 8px 12px; border-radius: 4px; width: 100%; margin: 4px 0 12px; }
        button { background: #0f3460; color: #fff; border: none; padding: 10px 20px;
                 border-radius: 4px; cursor: pointer; }
        button:hover { background: #1a5276; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #2a2a4a; }
        th { color: #00d2ff; }
        .warning { background: #ff2d55; color: #fff; padding: 12px; border-radius: 8px;
                   text-align: center; margin-bottom: 24px; font-weight: bold; }
        h1, h2 { color: #00d2ff; }
        .error { color: #ff6b35; background: rgba(255,107,53,0.1); padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="warning">FOR SECURITY TESTING ONLY - Intentionally Vulnerable Application</div>
    <nav>
        <a href="/">Home</a>
        <a href="/search">Search</a>
        <a href="/login">Login</a>
        <a href="/posts">Blog</a>
        <a href="/profile?user=admin">Profile</a>
        <a href="/file?name=about.txt">About</a>
        <a href="/guestbook">Guestbook</a>
        <a href="/admin">Admin</a>
    </nav>
    {{ content }}
</body>
</html>
"""


def render(content):
    from markupsafe import Markup
    return render_template_string(BASE_TEMPLATE, content=Markup(content))


# ==================== Routes ====================

@app.route("/")
def index():
    resp = make_response(render("""
        <h1>TestLab - Vulnerable Web Application</h1>
        <div class="card">
            <h2>Vulnerabilities Present:</h2>
            <ul>
                <li><strong>SQL Injection</strong> - /search, /login, /profile</li>
                <li><strong>Cross-Site Scripting (XSS)</strong> - /search, /guestbook, /profile</li>
                <li><strong>Path Traversal</strong> - /file</li>
                <li><strong>Missing Security Headers</strong> - All pages</li>
                <li><strong>Hidden Directories</strong> - /admin, /backup, /debug</li>
            </ul>
        </div>
    """))
    # Intentionally set insecure cookie
    resp.set_cookie("session_id", "abc123insecure", httponly=False)
    return resp


# ----- SQL Injection: Search -----
@app.route("/search")
def search():
    query = request.args.get("q", "")
    results_html = ""

    if query:
        conn = get_db()
        try:
            # VULNERABLE: Direct string concatenation in SQL
            sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
            results = conn.execute(sql).fetchall()
            if results:
                results_html = "<h2>Results:</h2>"
                for row in results:
                    results_html += f'<div class="card"><h3>{row["title"]}</h3><p>{row["content"]}</p><small>By: {row["author"]}</small></div>'
            else:
                results_html = f'<p>No results for: {query}</p>'
        except Exception as e:
            # VULNERABLE: Exposes SQL error messages
            results_html = f'<div class="error">Database error: {e}</div>'
        conn.close()

    return render(f"""
        <h1>Search Posts</h1>
        <div class="card">
            <form method="GET" action="/search">
                <input type="text" name="q" placeholder="Search posts..." value="{query}">
                <button type="submit">Search</button>
            </form>
        </div>
        {results_html}
    """)


# ----- SQL Injection: Login -----
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        try:
            # VULNERABLE: SQL Injection in login
            sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            user = conn.execute(sql).fetchone()
            if user:
                message = f'<div class="card" style="border-color: #27ae60;">Welcome back, {user["username"]}! Role: {user["role"]}</div>'
            else:
                message = '<div class="error">Invalid credentials</div>'
        except Exception as e:
            message = f'<div class="error">Database error: {e}</div>'
        conn.close()

    return render(f"""
        <h1>Login</h1>
        <div class="card">
            <form method="POST" action="/login">
                <label>Username:</label>
                <input type="text" name="username" placeholder="Username">
                <label>Password:</label>
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
        </div>
        {message}
    """)


# ----- XSS + SQLi: Profile -----
@app.route("/profile")
def profile():
    user = request.args.get("user", "")
    user_html = ""

    if user:
        conn = get_db()
        try:
            # VULNERABLE: SQL Injection
            sql = f"SELECT * FROM users WHERE username='{user}'"
            result = conn.execute(sql).fetchone()
            if result:
                user_html = f"""
                <div class="card">
                    <h2>{result['username']}</h2>
                    <p>Email: {result['email']}</p>
                    <p>Role: {result['role']}</p>
                </div>
                """
            else:
                # VULNERABLE: Reflected XSS - user input rendered directly
                user_html = f'<div class="error">User not found: {user}</div>'
        except Exception as e:
            user_html = f'<div class="error">Error: {e}</div>'
        conn.close()

    return render(f"""
        <h1>User Profile</h1>
        <div class="card">
            <form method="GET" action="/profile">
                <input type="text" name="user" placeholder="Enter username..." value="">
                <button type="submit">View Profile</button>
            </form>
        </div>
        {user_html}
    """)


# ----- XSS: Guestbook (Stored XSS) -----
@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    conn = get_db()

    if request.method == "POST":
        name = request.form.get("name", "Anonymous")
        comment = request.form.get("comment", "")
        if comment:
            # VULNERABLE: Stores unescaped user input
            conn.execute("INSERT INTO comments (post_id, name, comment) VALUES (0, ?, ?)", (name, comment))
            conn.commit()

    comments = conn.execute("SELECT * FROM comments WHERE post_id=0 ORDER BY id DESC").fetchall()
    conn.close()

    comments_html = ""
    for c in comments:
        # VULNERABLE: Renders stored XSS
        comments_html += f'<div class="card"><strong>{c["name"]}</strong><p>{c["comment"]}</p></div>'

    return render(f"""
        <h1>Guestbook</h1>
        <div class="card">
            <form method="POST" action="/guestbook">
                <label>Name:</label>
                <input type="text" name="name" placeholder="Your name">
                <label>Comment:</label>
                <textarea name="comment" rows="3" placeholder="Leave a comment..."></textarea>
                <button type="submit">Post</button>
            </form>
        </div>
        <h2>Comments</h2>
        {comments_html}
    """)


# ----- Path Traversal -----
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    content = ""

    if filename:
        # VULNERABLE: Direct file path usage without sanitization
        filepath = os.path.join("files", filename)
        try:
            with open(filepath, "r") as f:
                content = f.read()
        except FileNotFoundError:
            content = f"File not found: {filename}"
        except Exception as e:
            content = f"Error reading file: {e}"

    return render(f"""
        <h1>File Reader</h1>
        <div class="card">
            <form method="GET" action="/file">
                <input type="text" name="name" placeholder="Filename (e.g., about.txt)" value="{filename}">
                <button type="submit">Read File</button>
            </form>
        </div>
        <div class="card"><pre>{content}</pre></div>
    """)


# ----- Blog Posts -----
@app.route("/posts")
def posts():
    conn = get_db()
    all_posts = conn.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    conn.close()

    posts_html = ""
    for p in all_posts:
        posts_html += f'<div class="card"><h3>{p["title"]}</h3><p>{p["content"]}</p><small>By: {p["author"]}</small></div>'

    return render(f"""
        <h1>Blog Posts</h1>
        {posts_html}
    """)


# ----- Hidden pages for directory bruteforce -----
@app.route("/admin")
def admin_panel():
    return render("""
        <h1>Admin Panel</h1>
        <div class="card">
            <p>Admin dashboard - restricted area</p>
            <table>
                <tr><th>User</th><th>Role</th><th>Email</th></tr>
                <tr><td>admin</td><td>admin</td><td>admin@example.com</td></tr>
                <tr><td>john</td><td>user</td><td>john@example.com</td></tr>
                <tr><td>alice</td><td>user</td><td>alice@example.com</td></tr>
            </table>
        </div>
    """)


@app.route("/backup")
def backup():
    return render("""
        <h1>Backup Directory</h1>
        <div class="card">
            <p>backup_2024_01.sql (2.3 MB)</p>
            <p>backup_2024_02.sql (2.5 MB)</p>
            <p>db_dump_full.sql (5.1 MB)</p>
        </div>
    """)


@app.route("/debug")
def debug():
    return render(f"""
        <h1>Debug Info</h1>
        <div class="card">
            <pre>Python: {os.sys.version}
OS: {os.name}
CWD: {os.getcwd()}
DB: {DB_PATH}</pre>
        </div>
    """)


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /debug\n", 200, {"Content-Type": "text/plain"}


@app.route("/.env")
def env_file():
    return "DB_HOST=localhost\nDB_USER=root\nDB_PASS=supersecret123\nSECRET_KEY=mysecretkey\nAPI_KEY=sk-1234567890\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    init_db()

    # Create sample files for path traversal
    files_dir = os.path.join(os.path.dirname(__file__), "files")
    os.makedirs(files_dir, exist_ok=True)
    about_file = os.path.join(files_dir, "about.txt")
    if not os.path.exists(about_file):
        with open(about_file, "w") as f:
            f.write("TestLab v1.0 - A deliberately vulnerable web application for security testing.\n")

    print("[*] TestLab starting on http://127.0.0.1:5000")
    print("[*] This app is INTENTIONALLY VULNERABLE - for testing only!")
    print("[*] Press Ctrl+C to stop\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
