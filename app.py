import os
from datetime import datetime, date

from flask import (
    Flask, request, redirect, url_for, flash, abort,
    send_from_directory, render_template_string
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import UniqueConstraint

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # Local fallback only. On Render, set DATABASE_URL to your PostgreSQL connection string.
    database_url = "sqlite:///" + os.path.join(BASE_DIR, "ricknet.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# -------------------- MODELS --------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(30), unique=True, nullable=False, index=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)
    net_credits = db.Column(db.Float, default=0.0, nullable=False)
    is_developer = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("VPNFile", backref="owner", lazy=True, cascade="all, delete-orphan")
    votes = db.relationship("Vote", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class VPNFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    vpn_type = db.Column(db.String(100), nullable=False)
    network = db.Column(db.String(100), nullable=False)
    expiry = db.Column(db.Date, nullable=True)
    description = db.Column(db.Text, nullable=True)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    original_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    votes = db.relationship("Vote", backref="vpn_file", lazy=True, cascade="all, delete-orphan")

    @property
    def is_expired(self):
        return self.expiry is not None and self.expiry < date.today()

    @property
    def working_votes(self):
        return sum(1 for vote in self.votes if vote.status == "working")

    @property
    def expired_votes(self):
        return sum(1 for vote in self.votes if vote.status == "expired")

    @property
    def not_working_votes(self):
        return sum(1 for vote in self.votes if vote.status == "not_working")


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey("vpn_file.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "file_id", name="unique_user_vote_per_file"),
    )


# -------------------- LOGIN --------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# -------------------- HELPERS --------------------

def developer_required():
    if not current_user.is_authenticated or not current_user.is_developer:
        abort(403)


def save_uploaded_file(uploaded_file):
    original = secure_filename(uploaded_file.filename)
    if not original:
        raise ValueError("Please choose a valid file.")

    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    stored = f"{timestamp}_{original}"
    uploaded_file.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
    return stored, original


# -------------------- TEMPLATE --------------------

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title or "RickNet Free Data" }}</title>
<style>
*{box-sizing:border-box} body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:#e8eef7}
a{color:inherit;text-decoration:none}.nav{background:#0b1728;padding:14px 5%;display:flex;gap:16px;align-items:center;flex-wrap:wrap;border-bottom:1px solid #22324a}
.brand{font-weight:800;font-size:21px;color:#4ee1a0}.navlinks{display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-left:auto}
.container{max-width:1050px;margin:28px auto;padding:0 16px}.card{background:#0d1b2e;border:1px solid #22324a;border-radius:16px;padding:20px;margin-bottom:16px}
h1,h2,h3{margin-top:0}.muted{color:#9db0c9}.badge{display:inline-block;background:#f4c542;color:#151515;padding:3px 8px;border-radius:999px;font-size:12px;font-weight:bold}
.credit{color:#4ee1a0;font-weight:bold}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
input,textarea,select{width:100%;padding:12px;border-radius:10px;border:1px solid #334763;background:#07111f;color:#fff;margin:6px 0 14px}
button,.btn{display:inline-block;border:0;border-radius:10px;padding:11px 15px;background:#27b978;color:white;font-weight:bold;cursor:pointer}
.btn.secondary{background:#334763}.btn.danger{background:#c94343}.btn.yellow{background:#e6ae2d;color:#111}
.flash{padding:12px;border-radius:10px;margin-bottom:14px;background:#253b5a}.stats{display:flex;gap:8px;flex-wrap:wrap}
.stat{padding:8px 10px;border-radius:9px;background:#13253d}.working{color:#4ee1a0}.expired{color:#f4c542}.broken{color:#ff6b6b}
.profile{display:flex;gap:14px;align-items:center}.avatar{width:64px;height:64px;border-radius:50%;object-fit:cover;background:#22324a}
.small{font-size:13px}.hero{padding:35px 20px;text-align:center;background:linear-gradient(135deg,#0d1b2e,#123a46);border-radius:20px}
table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #22324a;text-align:left}
@media(max-width:600px){.navlinks{margin-left:0}.container{margin-top:16px}}
</style>
</head>
<body>
<nav class="nav">
  <a class="brand" href="{{ url_for('home') }}">RickNet Free Data</a>
  <div class="navlinks">
    <a href="{{ url_for('home') }}">Home</a>
    <a href="{{ url_for('explore') }}">Explore</a>
    {% if current_user.is_authenticated %}
      <a href="{{ url_for('upload') }}">Upload</a>
      <a href="{{ url_for('profile') }}">Profile</a>
      {% if current_user.is_developer %}<a href="{{ url_for('developer_panel') }}">Developer Panel</a>{% endif %}
      <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a href="{{ url_for('register') }}">Register</a>
      <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
  </div>
</nav>
<main class="container">
{% with messages = get_flashed_messages() %}
  {% if messages %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endif %}
{% endwith %}
{{ body|safe }}
</main>
</body>
</html>
"""

def page(body, title="RickNet Free Data", **context):
    return render_template_string(
        BASE_TEMPLATE,
        body=render_template_string(body, **context),
        title=title,
        **context
    )


# -------------------- ROUTES --------------------

@app.route("/")
def home():
    recent_files = VPNFile.query.order_by(VPNFile.uploaded_at.desc()).limit(6).all()
    body = """
    <section class="hero">
      <h1>RickNet Free Data</h1>
      <p class="muted">Share and discover VPN configuration files from the community.</p>
      <a class="btn" href="{{ url_for('explore') }}">Explore Files</a>
      {% if current_user.is_authenticated %}<a class="btn secondary" href="{{ url_for('upload') }}">Upload a File</a>{% endif %}
    </section>
    <br>
    <h2>Latest uploads</h2>
    <div class="grid">
    {% for f in files %}
      <div class="card">
        <h3>{{ f.title }}</h3>
        <p class="muted">{{ f.vpn_type }} • {{ f.network }}</p>
        {% if f.is_expired %}<p class="expired">Expired</p>{% else %}<p class="working">Active</p>{% endif %}
        <a class="btn secondary" href="{{ url_for('file_detail', file_id=f.id) }}">View</a>
      </div>
    {% else %}
      <p class="muted">No files uploaded yet.</p>
    {% endfor %}
    </div>
    """
    return page(body, files=recent_files)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(phone) < 6 or len(username) < 3 or len(password) < 6:
            flash("Use a valid phone number, username (3+ characters), and password (6+ characters).")
        elif User.query.filter((User.phone == phone) | (User.username == username)).first():
            flash("That phone number or username is already registered.")
        else:
            user = User(phone=phone, username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Account created successfully.")
            return redirect(url_for("profile"))

    body = """
    <div class="card" style="max-width:520px;margin:auto">
      <h1>Create account</h1>
      <form method="post">
        <label>Phone number</label><input name="phone" required placeholder="+263...">
        <label>Username</label><input name="username" required>
        <label>Password</label><input type="password" name="password" required>
        <button>Create Account</button>
      </form>
    </div>
    """
    return page(body, "Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == identifier) | (User.phone == identifier)
        ).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("home"))

        flash("Invalid login details.")

    body = """
    <div class="card" style="max-width:520px;margin:auto">
      <h1>Login</h1>
      <form method="post">
        <label>Username or phone number</label><input name="identifier" required>
        <label>Password</label><input type="password" name="password" required>
        <button>Login</button>
      </form>
    </div>
    """
    return page(body, "Login")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        picture = request.files.get("profile_picture")
        if picture and picture.filename:
            try:
                stored, _ = save_uploaded_file(picture)
                current_user.profile_picture = stored
                db.session.commit()
                flash("Profile picture updated.")
            except ValueError as e:
                flash(str(e))

    body = """
    <div class="card">
      <div class="profile">
        {% if current_user.profile_picture %}
          <img class="avatar" src="{{ url_for('uploaded_file', filename=current_user.profile_picture) }}">
        {% else %}
          <div class="avatar"></div>
        {% endif %}
        <div>
          <h1>{{ current_user.username }} {% if current_user.is_developer %}<span class="badge">DEVELOPER</span>{% endif %}</h1>
          <p class="muted">{{ current_user.phone }}</p>
          <p class="credit">🪙 {{ "%.2f"|format(current_user.net_credits) }} Net Credits</p>
        </div>
      </div>
      <hr style="border-color:#22324a">
      <form method="post" enctype="multipart/form-data">
        <label>Change profile picture</label>
        <input type="file" name="profile_picture" accept="image/*">
        <button>Update Picture</button>
      </form>
    </div>
    <div class="card">
      <h2>Your uploads</h2>
      {% for f in current_user.files|sort(attribute='uploaded_at', reverse=true) %}
        <p><a href="{{ url_for('file_detail', file_id=f.id) }}">{{ f.title }}</a> — {{ f.vpn_type }} / {{ f.network }}</p>
      {% else %}
        <p class="muted">You have not uploaded any files yet.</p>
      {% endfor %}
    </div>
    """
    return page(body, "Profile")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        vpn_type = request.form.get("vpn_type", "").strip()
        network = request.form.get("network", "").strip()
        expiry_raw = request.form.get("expiry", "").strip()
        description = request.form.get("description", "").strip()
        uploaded = request.files.get("vpn_file")

        if not title or not vpn_type or not network or not uploaded or not uploaded.filename:
            flash("Please complete all required fields and choose a file.")
        else:
            try:
                expiry = datetime.strptime(expiry_raw, "%Y-%m-%d").date() if expiry_raw else None
                stored, original = save_uploaded_file(uploaded)

                vpn_file = VPNFile(
                    title=title,
                    vpn_type=vpn_type,
                    network=network,
                    expiry=expiry,
                    description=description,
                    stored_filename=stored,
                    original_filename=original,
                    user_id=current_user.id
                )
                db.session.add(vpn_file)

                # Reward only after a successful upload record is created.
                current_user.net_credits += 0.02
                db.session.commit()

                flash("Upload successful! You earned +0.02 Net Credits.")
                return redirect(url_for("file_detail", file_id=vpn_file.id))
            except ValueError as e:
                flash(str(e))

    body = """
    <div class="card" style="max-width:650px;margin:auto">
      <h1>Upload VPN File</h1>
      <p class="muted">Enter your own VPN type and network name.</p>
      <form method="post" enctype="multipart/form-data">
        <label>File title</label><input name="title" required placeholder="Example config">
        <label>Which VPN?</label><input name="vpn_type" required placeholder="Type any VPN app">
        <label>Which network?</label><input name="network" required placeholder="Type any network">
        <label>Expiry date (optional)</label><input type="date" name="expiry">
        <label>Description (optional)</label><textarea name="description" rows="4"></textarea>
        <label>Choose file</label><input type="file" name="vpn_file" required>
        <button>Upload and Earn +0.02 Credits</button>
      </form>
    </div>
    """
    return page(body, "Upload")


@app.route("/explore")
def explore():
    network = request.args.get("network", "").strip()
    vpn_type = request.args.get("vpn_type", "").strip()

    query = VPNFile.query
    if network:
        query = query.filter(VPNFile.network.ilike(f"%{network}%"))
    if vpn_type:
        query = query.filter(VPNFile.vpn_type.ilike(f"%{vpn_type}%"))

    files = query.order_by(VPNFile.uploaded_at.desc()).all()

    body = """
    <h1>Explore VPN Files</h1>
    <div class="card">
      <form method="get">
        <div class="grid">
          <div><label>Network</label><input name="network" value="{{ network }}" placeholder="Search network"></div>
          <div><label>VPN type</label><input name="vpn_type" value="{{ vpn_type }}" placeholder="Search VPN"></div>
        </div>
        <button>Search</button>
      </form>
    </div>
    <div class="grid">
    {% for f in files %}
      <div class="card">
        <h3>{{ f.title }}</h3>
        <p>{{ f.vpn_type }} • {{ f.network }}</p>
        <div class="stats small">
          <span class="stat working">🟢 {{ f.working_votes }}</span>
          <span class="stat expired">⏰ {{ f.expired_votes }}</span>
          <span class="stat broken">🔴 {{ f.not_working_votes }}</span>
        </div>
        <p class="muted small">By {{ f.owner.username }}{% if f.owner.is_developer %} <span class="badge">DEV</span>{% endif %}</p>
        <a class="btn" href="{{ url_for('file_detail', file_id=f.id) }}">Open</a>
      </div>
    {% else %}
      <p class="muted">No matching files found.</p>
    {% endfor %}
    </div>
    """
    return page(body, "Explore", files=files, network=network, vpn_type=vpn_type)


@app.route("/file/<int:file_id>")
def file_detail(file_id):
    vpn_file = db.session.get(VPNFile, file_id)
    if not vpn_file:
        abort(404)

    user_vote = None
    if current_user.is_authenticated:
        user_vote = Vote.query.filter_by(
            user_id=current_user.id, file_id=vpn_file.id
        ).first()

    body = """
    <div class="card">
      <h1>{{ f.title }}</h1>
      <p class="muted">{{ f.vpn_type }} • {{ f.network }}</p>
      <p>{{ f.description or "No description provided." }}</p>
      <p><b>Expiry:</b> {{ f.expiry or "Not specified" }}</p>
      <p><b>Uploader:</b> {{ f.owner.username }} {% if f.owner.is_developer %}<span class="badge">DEVELOPER</span>{% endif %}</p>

      {% if not f.is_expired %}
        <a class="btn" href="{{ url_for('download_file', file_id=f.id) }}">📥 Download File</a>
      {% else %}
        <span class="btn secondary">File expired — download disabled</span>
      {% endif %}
    </div>

    <div class="card">
      <h2>Community Poll</h2>
      <div class="stats">
        <span class="stat working">🟢 Working: {{ f.working_votes }}</span>
        <span class="stat expired">⏰ Expired: {{ f.expired_votes }}</span>
        <span class="stat broken">🔴 Not Working: {{ f.not_working_votes }}</span>
      </div>
      {% if current_user.is_authenticated %}
        <form method="post" action="{{ url_for('vote', file_id=f.id) }}" style="margin-top:14px">
          <button name="status" value="working">🟢 Working</button>
          <button class="yellow" name="status" value="expired">⏰ Expired</button>
          <button class="danger" name="status" value="not_working">🔴 Not Working</button>
        </form>
        <p class="muted small">Your current vote: {{ user_vote.status if user_vote else "No vote yet" }}. You can change it anytime.</p>
      {% else %}
        <p class="muted">Login to vote.</p>
      {% endif %}
    </div>
    """
    return page(body, vpn_file.title, f=vpn_file, user_vote=user_vote)


@app.route("/file/<int:file_id>/vote", methods=["POST"])
@login_required
def vote(file_id):
    vpn_file = db.session.get(VPNFile, file_id)
    if not vpn_file:
        abort(404)

    status = request.form.get("status")
    if status not in {"working", "expired", "not_working"}:
        flash("Invalid vote.")
        return redirect(url_for("file_detail", file_id=file_id))

    existing = Vote.query.filter_by(
        user_id=current_user.id, file_id=file_id
    ).first()

    if existing:
        existing.status = status
        flash("Your vote was updated.")
    else:
        db.session.add(Vote(status=status, user_id=current_user.id, file_id=file_id))
        flash("Your vote was recorded.")

    db.session.commit()
    return redirect(url_for("file_detail", file_id=file_id))


@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    vpn_file = db.session.get(VPNFile, file_id)
    if not vpn_file:
        abort(404)

    if vpn_file.is_expired:
        flash("This file has expired and cannot be downloaded.")
        return redirect(url_for("file_detail", file_id=file_id))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        vpn_file.stored_filename,
        as_attachment=True,
        download_name=vpn_file.original_filename
    )


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# -------------------- DEVELOPER PANEL --------------------

@app.route("/developer")
@login_required
def developer_panel():
    developer_required()

    users = User.query.order_by(User.created_at.desc()).all()
    files = VPNFile.query.order_by(VPNFile.uploaded_at.desc()).all()

    body = """
    <h1>👑 Developer Panel</h1>
    <div class="grid">
      <div class="card"><h2>{{ users|length }}</h2><p class="muted">Users</p></div>
      <div class="card"><h2>{{ files|length }}</h2><p class="muted">Files</p></div>
      <div class="card"><h2>{{ dev_count }}</h2><p class="muted">Developers</p></div>
    </div>

    <div class="card">
      <h2>Manage developer accounts</h2>
      <table>
        <tr><th>User</th><th>Phone</th><th>Developer</th><th>Action</th></tr>
        {% for u in users %}
        <tr>
          <td>{{ u.username }}</td>
          <td>{{ u.phone }}</td>
          <td>{% if u.is_developer %}⭐ Yes{% else %}No{% endif %}</td>
          <td>
            {% if u.id != current_user.id %}
            <form method="post" action="{{ url_for('toggle_developer', user_id=u.id) }}">
              <button class="secondary">{% if u.is_developer %}Remove Dev{% else %}Make Dev{% endif %}</button>
            </form>
            {% else %}<span class="muted">You</span>{% endif %}
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>
    """
    return page(
        body, "Developer Panel",
        users=users,
        files=files,
        dev_count=sum(1 for u in users if u.is_developer)
    )


@app.route("/developer/user/<int:user_id>/toggle", methods=["POST"])
@login_required
def toggle_developer(user_id):
    developer_required()

    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    if user.id == current_user.id:
        flash("You cannot remove your own developer status here.")
        return redirect(url_for("developer_panel"))

    user.is_developer = not user.is_developer
    db.session.commit()
    flash(f"Developer status updated for {user.username}.")
    return redirect(url_for("developer_panel"))


# -------------------- STARTUP --------------------

with app.app_context():
    db.create_all()

    # The first developer is controlled through an environment variable.
    # Example on Render: DEVELOPER_PHONE=263xxxxxxxxx
    developer_phone = os.environ.get("DEVELOPER_PHONE")
    if developer_phone:
        first_dev = User.query.filter_by(phone=developer_phone).first()
        if first_dev and not first_dev.is_developer:
            first_dev.is_developer = True
            db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)
