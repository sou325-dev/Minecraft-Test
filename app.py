from flask import Flask, render_template, request, redirect, session, jsonify, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

DB_PATH = "database.db"
SECRET_KEY = os.environ.get("MINECRAFT_SECRET") or "change_this_secret!"

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET_KEY

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    c = db.cursor()
    # users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        best_level INTEGER NOT NULL DEFAULT 10,
        is_admin INTEGER NOT NULL DEFAULT 0
    );
    """)
    # history table
    c.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        level_before INTEGER NOT NULL,
        level_after INTEGER NOT NULL,
        score INTEGER NOT NULL,
        total INTEGER NOT NULL,
        passed INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    db.commit()
    # create default admin if not exists
    c.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        pw = generate_password_hash("admin123")
        c.execute("INSERT INTO users(username,password,best_level,is_admin) VALUES(?,?,?,1)", ("admin", pw, 10))
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

# helper
def find_user_by_name(username):
    c = get_db().cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    return c.fetchone()

def find_user_by_id(uid):
    c = get_db().cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return c.fetchone()

def update_user_best_level(user_id, new_level):
    db = get_db()
    c = db.cursor()
    c.execute("UPDATE users SET best_level = ? WHERE id = ?", (new_level, user_id))
    db.commit()

def insert_history(user_id, level_before, level_after, score, total, passed):
    db = get_db()
    c = db.cursor()
    c.execute(
        "INSERT INTO history(user_id,level_before,level_after,score,total,passed,created_at) VALUES(?,?,?,?,?,?,?)",
        (user_id, level_before, level_after, score, total, int(passed), datetime.utcnow().isoformat())
    )
    db.commit()

@app.before_request
def before_request():
    get_db()
    init_db()

# routes
@app.route("/")
def root():
    if "user_id" in session:
        return redirect("/exam")
    return redirect("/login")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = find_user_by_name(username)
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["best_level"] = user["best_level"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect("/exam")
        else:
            return render_template("login.html", error="ユーザー名またはパスワードが違います。")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not username or not password:
            return render_template("register.html", error="ユーザー名とパスワードは必須です。")
        if find_user_by_name(username):
            return render_template("register.html", error="そのユーザー名は既に使われています。")
        pw_hash = generate_password_hash(password)
        db = get_db()
        c = db.cursor()
        c.execute("INSERT INTO users(username,password,best_level) VALUES(?,?,10)", (username, pw_hash))
        db.commit()
        return redirect("/login")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/exam")
def exam():
    if "user_id" not in session:
        return redirect("/login")
    # render index.html and pass user info
    return render_template("index.html", username=session.get("username"), best_level=session.get("best_level", 10), is_admin=session.get("is_admin", False))

# API to update best level
@app.route("/api/update_level", methods=["POST"])
def api_update_level():
    if "user_id" not in session:
        return jsonify({"status":"error","message":"not logged in"}), 403
    payload = request.get_json() or {}
    new_level = payload.get("level")
    try:
        new_level_int = int(new_level)
    except:
        return jsonify({"status":"error","message":"invalid level"}), 400
    user_id = session["user_id"]
    user = find_user_by_id(user_id)
    if user:
        current_best = user["best_level"]
        # smaller number is better (1級 is best)
        if new_level_int < current_best:
            update_user_best_level(user_id, new_level_int)
            session["best_level"] = new_level_int
    return jsonify({"status":"ok","best_level": session.get("best_level")})

# API to record result
@app.route("/api/record_result", methods=["POST"])
def api_record_result():
    if "user_id" not in session:
        return jsonify({"status":"error","message":"not logged in"}), 403
    payload = request.get_json() or {}
    try:
        level_before = int(payload.get("level_before"))
        level_after = int(payload.get("level_after"))
        score = int(payload.get("score"))
        total = int(payload.get("total"))
        passed = bool(payload.get("passed"))
    except Exception as e:
        return jsonify({"status":"error","message":"invalid payload"}), 400
    try:
        insert_history(session["user_id"], level_before, level_after, score, total, passed)
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500
    return jsonify({"status":"ok"})

# Admin page
@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect("/login")
    if not session.get("is_admin"):
        return "管理者のみアクセス可", 403
    db = get_db()
    c = db.cursor()
    c.execute("SELECT username,best_level FROM users ORDER BY best_level ASC, username ASC")
    ranking = c.fetchall()
    c.execute("""
      SELECT h.*, u.username FROM history h
      JOIN users u ON u.id = h.user_id
      ORDER BY created_at DESC LIMIT 200
    """)
    hist = c.fetchall()
    return render_template("admin.html", ranking=ranking, history=hist)

if __name__ == "__main__":
    with app.app_context():
        init_db()
    # 指定 IP とポートで起動
    app.run(host="192.168.3.25", port=5000, debug=True)

