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
    is_moderator = db.Column(db.Boolean, default=False, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("VPNFile", backref="owner", lazy=True, cascade="all, delete-orphan")
    votes = db.relationship("Vote", backref="user", lazy=True, cascade="all, delete-orphan")
    sni_purchases = db.relationship("SniPurchase", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class VPNFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    vpn_type = db.Column(db.String(100), nullable=False)
    network = db.Column(db.String(100), nullable=False)
    host_sni = db.Column(db.String(255), nullable=True)
    expiry = db.Column(db.Date, nullable=True)
    description = db.Column(db.Text, nullable=True)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    original_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    votes = db.relationship("Vote", backref="vpn_file", lazy=True, cascade="all, delete-orphan")
    sni_purchases = db.relationship("SniPurchase", backref="vpn_file", lazy=True, cascade="all, delete-orphan")

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



class SniPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey("vpn_file.id"), nullable=False)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "file_id", name="unique_user_sni_purchase"),
    )


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


def moderator_required():
    if not current_user.is_authenticated or not (current_user.is_developer or current_user.is_moderator):
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
*{box-sizing:border-box}
:root{--bg:#07111f;--panel:#0d1b2e;--panel2:#10243b;--line:#22324a;--text:#e8eef7;--muted:#9db0c9;--green:#38d996;--blue:#2589ff;--purple:#7c3aed;--red:#e05252;--yellow:#f4c542}
body{margin:0;font-family:Arial,sans-serif;background:radial-gradient(circle at top right,#12394a 0,#07111f 38%,#07111f 100%);color:var(--text);min-height:100vh}
a{color:inherit;text-decoration:none}
.nav{position:sticky;top:0;z-index:10;background:rgba(11,23,40,.96);backdrop-filter:blur(12px);padding:15px 5%;display:flex;gap:16px;align-items:center;flex-wrap:wrap;border-bottom:1px solid var(--line)}
.brand{font-weight:900;font-size:23px;color:var(--green);letter-spacing:.2px;text-shadow:0 0 18px rgba(56,217,150,.18)}
.navlinks{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-left:auto}
.navlinks a{padding:9px 12px;border-radius:10px;font-weight:700;color:#c8d5e6;transition:.2s}
.navlinks a:hover{background:#172b45;color:#fff;transform:translateY(-1px)}
.container{max-width:1100px;margin:28px auto;padding:0 16px}
.card{background:linear-gradient(145deg,var(--panel),#0a1728);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:16px;box-shadow:0 12px 30px rgba(0,0,0,.12)}
h1,h2,h3{margin-top:0}.muted{color:var(--muted)}
.badge{display:inline-block;background:var(--yellow);color:#151515;padding:3px 8px;border-radius:999px;font-size:12px;font-weight:bold}
.badge.blue{background:var(--blue);color:#fff}.badge.mod{background:#8b5cf6;color:#fff}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:13px;padding:12px 16px;background:linear-gradient(135deg,#27b978,#38d996);color:white;font-weight:800;cursor:pointer;box-shadow:0 8px 18px rgba(39,185,120,.18);transition:transform .18s,box-shadow .18s,filter .18s}
.btn:hover{transform:translateY(-2px);filter:brightness(1.06);box-shadow:0 12px 24px rgba(39,185,120,.25)}
.btn.big{padding:14px 18px;border-radius:14px}.btn.purple{background:linear-gradient(135deg,#6d28d9,#8b5cf6)}.btn.blue{background:linear-gradient(135deg,#1677ff,#45a0ff)}.btn.green{background:linear-gradient(135deg,#159f67,#38d996)}.btn.red,.btn.danger{background:linear-gradient(135deg,#c94343,#ef6262)}.btn.yellow{background:linear-gradient(135deg,#e6ae2d,#ffd15c);color:#111}.btn.secondary{background:linear-gradient(135deg,#334763,#465b79);box-shadow:0 8px 18px rgba(0,0,0,.18)}
.credit{color:var(--green);font-weight:bold}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
input,textarea,select{width:100%;padding:12px;border-radius:10px;border:1px solid #334763;background:#07111f;color:#fff;margin:6px 0 14px}
.flash{padding:12px;border-radius:10px;margin-bottom:14px;background:#253b5a;border:1px solid #3b5272}
.stats{display:flex;gap:8px;flex-wrap:wrap}.stat{padding:8px 10px;border-radius:9px;background:#13253d}.working{color:#4ee1a0}.expired{color:#f4c542}.broken{color:#ff6b6b}
.profile{display:flex;gap:14px;align-items:center}.avatar{width:64px;height:64px;border-radius:50%;object-fit:cover;background:#22324a}
.award-form{display:flex;gap:6px;align-items:center}.award-form input{width:100px;padding:8px}.small{font-size:13px}
.hero{position:relative;overflow:hidden;padding:42px 24px;text-align:center;background:linear-gradient(135deg,#0b1d32,#124555);border-radius:24px;border:1px solid #245065}
.hero:before{content:"";position:absolute;width:280px;height:280px;border-radius:50%;background:rgba(56,217,150,.12);top:-150px;right:-100px;filter:blur(10px)}
.hero h1{position:relative;font-size:clamp(34px,6vw,58px);margin-bottom:12px}.hero p{position:relative;font-size:18px;max-width:700px;margin:0 auto 24px}
.hero-actions{position:relative;display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.home-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}
.home-stat{background:rgba(10,24,42,.8);border:1px solid var(--line);border-radius:16px;padding:16px;text-align:center}.home-stat b{display:block;font-size:25px;color:var(--green);margin-top:5px}
.section-title{display:flex;justify-content:space-between;align-items:center;gap:10px;margin:28px 0 14px}
.quick-card{padding:22px;border-radius:18px;background:linear-gradient(145deg,#10243b,#0b1829);border:1px solid var(--line);transition:.2s;min-height:190px}
.quick-card:hover{transform:translateY(-4px);border-color:#3c5e7d}.quick-icon{font-size:34px;margin-bottom:12px}.quick-card h3{margin-bottom:8px}.quick-card p{min-height:42px}
.info-strip{background:linear-gradient(135deg,rgba(56,217,150,.12),rgba(37,137,255,.1));border:1px solid #28556a;border-radius:18px;padding:18px;margin-top:18px}
table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid var(--line);text-align:left}
@media(max-width:700px){.nav{padding:16px 24px}.brand{width:100%}.navlinks{margin-left:0}.navlinks a{padding:8px 10px}.home-stats{grid-template-columns:1fr}.container{margin-top:18px}.hero{padding:34px 18px}}
</style>
</head>
<body>
<nav class="nav">
  <a class="brand" href="{{ url_for('home') }}">RickNet Free Data</a>
  <div class="navlinks">
    <a href="{{ url_for('home') }}">🏠 Home</a>
    <a href="{{ url_for('explore') }}">🔎 Explore</a>
    {% if current_user.is_authenticated %}
      <a href="{{ url_for('upload') }}">📤 Upload</a>
      <a href="{{ url_for('profile') }}">👤 Profile</a>
      {% if current_user.is_developer %}<a href="{{ url_for('developer_panel') }}">👑 Developer</a>{% endif %}
      {% if current_user.is_moderator and not current_user.is_developer %}<a href="{{ url_for('moderator_panel') }}">🛡️ Moderator</a>{% endif %}
      <a href="{{ url_for('logout') }}">↩ Logout</a>
    {% else %}
      <a href="{{ url_for('register') }}">✨ Register</a>
      <a href="{{ url_for('login') }}">🔐 Login</a>
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


# -------------------- OWNER / CREDIT HELPERS --------------------

def is_rick_owner(user):
    if not user:
        return False
    if user.username and user.username.strip().lower() == "rick":
        return True
    developer_phone = os.environ.get("DEVELOPER_PHONE", "").strip()
    return bool(developer_phone and user.phone == developer_phone)


def display_credits(user):
    return "∞ Unlimited" if is_rick_owner(user) else f"{user.net_credits:.2f}"


# -------------------- ROUTES --------------------

@app.route("/")
def home():
    recent_files = VPNFile.query.order_by(VPNFile.uploaded_at.desc()).limit(6).all()
    total_files = VPNFile.query.count()
    total_users = User.query.count()
    active_files = sum(1 for item in VPNFile.query.all() if not item.is_expired)

    body = """
    <section class="hero">
      <h1>🚀 RickNet Free Data</h1>
      <p class="muted">Discover, share and rate VPN configuration files with the community. Find active configs for your network in one place.</p>
      <div class="hero-actions">
        <a class="btn big" href="{{ url_for('explore') }}">🔎 Explore Files</a>
        {% if current_user.is_authenticated %}
          <a class="btn big blue" href="{{ url_for('upload') }}">📤 Upload & Earn</a>
          <a class="btn big secondary" href="{{ url_for('profile') }}">👤 My Profile</a>
        {% else %}
          <a class="btn big blue" href="{{ url_for('register') }}">✨ Create Free Account</a>
          <a class="btn big secondary" href="{{ url_for('login') }}">🔐 Login</a>
        {% endif %}
      </div>
    </section>

    <div class="home-stats">
      <div class="home-stat">📁<b>{{ total_files }}</b><span class="muted">Files Shared</span></div>
      <div class="home-stat">🟢<b>{{ active_files }}</b><span class="muted">Active Files</span></div>
      <div class="home-stat">👥<b>{{ total_users }}</b><span class="muted">Community Members</span></div>
    </div>


    <section class="card">
      <h2>🌐 Join the RickNet Community</h2>
      <p class="muted">Get RickNet updates, new uploads and announcements.</p>
      <div class="hero-actions">
        <a class="btn big" href="https://whatsapp.com/channel/0029VbCi6tOEQIanTIOmEl1c" target="_blank" rel="noopener">💬 WhatsApp Channel</a>
        <a class="btn big blue" href="https://t.me/ricknetfreedata" target="_blank" rel="noopener">✈️ Telegram Channel</a>
      </div>
      
    </section>

    <div class="section-title">
      <div><h2 style="margin:0">⚡ Quick Actions</h2><p class="muted" style="margin:5px 0 0">Everything you need, one tap away.</p></div>
    </div>

    <div class="grid">
      <div class="quick-card">
        <div class="quick-icon">🔎</div>
        <h3>Explore VPN Files</h3>
        <p class="muted">Search files by VPN type or mobile network and check community votes.</p>
        <a class="btn secondary" href="{{ url_for('explore') }}">Browse Now →</a>
      </div>

      {% if current_user.is_authenticated %}
      <div class="quick-card">
        <div class="quick-icon">📤</div>
        <h3>Upload a Config</h3>
        <p class="muted">Share your working file with the community and earn +2.00 Net Credits.</p>
        <a class="btn" href="{{ url_for('upload') }}">Upload File →</a>
      </div>

      <div class="quick-card">
        <div class="quick-icon">👤</div>
        <h3>My RickNet Account</h3>
        <p class="muted">View your uploads, credits, badges and account status.</p>
        <a class="btn blue" href="{{ url_for('profile') }}">Open Profile →</a>
      </div>
      {% else %}
      <div class="quick-card">
        <div class="quick-icon">✨</div>
        <h3>Join RickNet</h3>
        <p class="muted">Create an account to view file details and download active files.</p>
        <a class="btn" href="{{ url_for('register') }}">Create Account →</a>
      </div>

      <div class="quick-card">
        <div class="quick-icon">🗳️</div>
        <h3>Community Ratings</h3>
        <p class="muted">Vote Working, Expired or Not Working after trying a shared file.</p>
        <a class="btn blue" href="{{ url_for('login') }}">Login to Vote →</a>
      </div>
      {% endif %}
    </div>

    <div class="info-strip">
      <b>🛡️ Community powered:</b>
      <span class="muted"> File ratings help other users quickly identify which configurations are still useful.</span>
    </div>

    <div class="section-title">
      <div><h2 style="margin:0">🔥 Latest Uploads</h2><p class="muted" style="margin:5px 0 0">Fresh files shared by the RickNet community.</p></div>
      <a class="btn secondary" href="{{ url_for('explore') }}">View All</a>
    </div>

    <div class="grid">
    {% for f in files %}
      <div class="card">
        <h3>{{ f.title }}</h3>
        <p class="muted">📱 {{ f.vpn_type }} &nbsp; • &nbsp; 📶 {{ f.network }}</p>
        {% if f.is_expired %}<p class="expired">⏰ Expired</p>{% else %}<p class="working">🟢 Active</p>{% endif %}
        <div class="stats small">
          <span class="stat working">🟢 {{ f.working_votes }}</span>
          <span class="stat expired">⏰ {{ f.expired_votes }}</span>
          <span class="stat broken">🔴 {{ f.not_working_votes }}</span>
        </div>
        <div class="actions"><a class="btn secondary" href="{{ url_for('file_detail', file_id=f.id) }}">View File →</a></div>
      </div>
    {% else %}
      <div class="card" style="grid-column:1/-1;text-align:center;padding:34px">
        <div style="font-size:42px">📂</div>
        <h3>No files uploaded yet</h3>
        <p class="muted">Be the first person to share a VPN configuration with the community.</p>
        {% if current_user.is_authenticated %}<a class="btn" href="{{ url_for('upload') }}">📤 Upload the First File</a>{% else %}<a class="btn" href="{{ url_for('register') }}">✨ Create an Account</a>{% endif %}
      </div>
    {% endfor %}
    </div>
    """
    return page(
        body,
        files=recent_files,
        total_files=total_files,
        total_users=total_users,
        active_files=active_files
    )

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
        {% else %}<div class="avatar"></div>{% endif %}
        <div>
          <h1>{{ current_user.username }}
            {% if current_user.is_developer %}<span class="badge blue">🔵 RICK VERIFIED · DEVELOPER</span>
            {% elif current_user.is_moderator %}<span class="badge mod">🛡️ MODERATOR</span>{% endif %}
            {% if current_user.is_verified %}<span class="badge blue">✓ VERIFIED</span>{% endif %}
          </h1>
          <p class="muted">{{ current_user.phone }}</p>
          <p class="credit">🪙 {% if owner_unlimited %}∞ Unlimited Net Credits{% else %}{{ "%.2f"|format(current_user.net_credits) }} Net Credits{% endif %}</p>
        </div>
      </div>
      <div class="actions">
        <a class="btn big blue" href="{{ url_for('upload') }}">📤 Upload File</a>
        <a class="btn big secondary" href="{{ url_for('explore') }}">🔎 Explore Files</a>
        {% if current_user.is_developer %}<a class="btn big purple" href="{{ url_for('developer_panel') }}">👑 Developer Panel</a>{% endif %}
        {% if current_user.is_moderator and not current_user.is_developer %}<a class="btn big purple" href="{{ url_for('moderator_panel') }}">🛡️ Moderator Panel</a>{% endif %}
        {% if not current_user.is_verified %}
          <form method="post" action="{{ url_for('verify_account') }}" style="display:inline">
            <button class="btn big yellow" onclick="return confirm('Spend 60 Net Credits to verify this account?')">⭐ Verify for 60 Credits</button>
          </form>
        {% endif %}
      </div>
      <hr style="border-color:#22324a">
      <form method="post" enctype="multipart/form-data">
        <label>Change profile picture</label>
        <input type="file" name="profile_picture" accept="image/*">
        <button class="btn green">🖼️ Update Picture</button>
      </form>
    </div>
    <div class="card">
      <h2>Your uploads</h2>
      {% for f in current_user.files|sort(attribute='uploaded_at', reverse=true) %}
        <p><a href="{{ url_for('file_detail', file_id=f.id) }}">{{ f.title }}</a> — {{ f.vpn_type }} / {{ f.network }}</p>
      {% else %}<p class="muted">You have not uploaded any files yet.</p>{% endfor %}
    </div>
    """
    return page(body, "Profile", owner_unlimited=is_rick_owner(current_user))


@app.route("/verify-account", methods=["POST"])
@login_required
def verify_account():
    if current_user.is_verified:
        flash("Your account is already verified.")
    elif not is_rick_owner(current_user) and current_user.net_credits < 60:
        flash("You need 60 Net Credits to verify your account.")
    else:
        if not is_rick_owner(current_user):
            current_user.net_credits -= 60
        current_user.is_verified = True
        db.session.commit()
        flash("Account verified successfully! A blue verified badge is now on your profile.")
    return redirect(url_for("profile"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        vpn_type = request.form.get("vpn_type", "").strip()
        network = request.form.get("network", "").strip()
        expiry_raw = request.form.get("expiry", "").strip()
        description = request.form.get("description", "").strip()
        host_sni = request.form.get("host_sni", "").strip()
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
                    host_sni=host_sni,
                    expiry=expiry,
                    description=description,
                    stored_filename=stored,
                    original_filename=original,
                    user_id=current_user.id
                )
                db.session.add(vpn_file)

                # Reward only after a successful upload record is created.
                current_user.net_credits += 2.00
                db.session.commit()

                flash("Upload successful! You earned +2.00 Net Credits.")
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
        <label>Host SNI (optional)</label><input name="host_sni" maxlength="255" placeholder="Example: example.com">
        <p class="muted small">🔐 Host SNI is hidden from other users until they unlock it for 15 Net Credits.</p>
        <label>Expiry date (optional)</label><input type="date" name="expiry">
        <label>Description (optional)</label><textarea name="description" rows="4"></textarea>
        <label>Choose file</label><input type="file" name="vpn_file" required>
        <button>Upload and Earn +2 Credits</button>
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
        <div class="actions">
          <a class="btn" href="{{ url_for('file_detail', file_id=f.id) }}">👁️ Open</a>
          {% if current_user.is_authenticated and current_user.is_developer %}
          <form method="post" action="{{ url_for('developer_delete_file', file_id=f.id) }}"
                onsubmit="return confirm('Delete {{ f.title|e }}? This cannot be undone.')">
            <button class="btn red" type="submit">🗑️ Delete</button>
          </form>
          {% endif %}
        </div>
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

      <div class="info-strip">
        {% if sni_unlocked %}
          <b>🔓 Host SNI:</b> <span>{{ f.host_sni or "Not provided" }}</span>
        {% elif f.host_sni %}
          <b>🔐 Host SNI:</b> <span class="muted">Locked — 15 Net Credits</span>
          {% if current_user.is_authenticated %}
            <div class="actions">
              <form method="post" action="{{ url_for('unlock_sni', file_id=f.id) }}"
                    onsubmit="return confirm('Spend 15 Net Credits to reveal the Host SNI?')">
                <button class="btn yellow" type="submit">🔓 Unlock Host SNI · 15 Credits</button>
              </form>
            </div>
          {% else %}
            <p class="muted small">Login to unlock the Host SNI.</p>
          {% endif %}
        {% else %}
          <b>Host SNI:</b> <span class="muted">Not provided by uploader.</span>
        {% endif %}
      </div>

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
    sni_unlocked = bool(
        current_user.is_authenticated and (
            is_rick_owner(current_user) or
            current_user.id == vpn_file.user_id or
            not vpn_file.host_sni or
            SniPurchase.query.filter_by(
                user_id=current_user.id, file_id=vpn_file.id
            ).first()
        )
    )
    return page(body, vpn_file.title, f=vpn_file, user_vote=user_vote, sni_unlocked=sni_unlocked)



@app.route("/file/<int:file_id>/unlock-sni", methods=["POST"])
@login_required
def unlock_sni(file_id):
    vpn_file = db.session.get(VPNFile, file_id)
    if not vpn_file:
        abort(404)

    if not vpn_file.host_sni:
        flash("This file does not have a Host SNI.")
        return redirect(url_for("file_detail", file_id=file_id))

    existing = SniPurchase.query.filter_by(
        user_id=current_user.id, file_id=file_id
    ).first()
    if existing or is_rick_owner(current_user) or current_user.id == vpn_file.user_id:
        flash("Host SNI is already available to your account.")
        return redirect(url_for("file_detail", file_id=file_id))

    if current_user.net_credits < 15:
        flash("You need 15 Net Credits to unlock this Host SNI.")
        return redirect(url_for("file_detail", file_id=file_id))

    current_user.net_credits -= 15
    db.session.add(SniPurchase(user_id=current_user.id, file_id=file_id))
    db.session.commit()
    flash("Host SNI unlocked! 15 Net Credits were used.")
    return redirect(url_for("file_detail", file_id=file_id))


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

    # Automatic cleanup: delete a file as soon as it reaches 5 Not Working votes.
    if vpn_file.not_working_votes >= 5:
        title = vpn_file.title
        path = os.path.join(app.config["UPLOAD_FOLDER"], vpn_file.stored_filename)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
        db.session.delete(vpn_file)
        db.session.commit()
        flash(f"'{title}' was automatically deleted after reaching 5 Not Working votes.")
        return redirect(url_for("explore"))

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



@app.route("/developer/file/<int:file_id>/delete", methods=["POST"])
@login_required
def developer_delete_file(file_id):
    developer_required()
    vpn_file = db.session.get(VPNFile, file_id)
    if not vpn_file:
        abort(404)
    path = os.path.join(app.config["UPLOAD_FOLDER"], vpn_file.stored_filename)
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
    title = vpn_file.title
    db.session.delete(vpn_file)
    db.session.commit()
    flash(f"Uploaded file '{title}' was deleted.")
    return redirect(url_for("developer_panel"))


# -------------------- DEVELOPER PANEL --------------------

@app.route("/developer")
@login_required
def developer_panel():
    developer_required()
    users = User.query.order_by(User.created_at.desc()).all()
    files = VPNFile.query.order_by(VPNFile.uploaded_at.desc()).all()
    body = """
    <h1>👑 RickNet Developer Panel</h1>
    <div class="grid">
      <div class="card"><h2>{{ users|length }}</h2><p class="muted">👥 Users</p></div>
      <div class="card"><h2>{{ files|length }}</h2><p class="muted">📁 Files</p></div>
      <div class="card"><h2>{{ dev_count }}</h2><p class="muted">👑 Developers</p></div>
      <div class="card"><h2>{{ mod_count }}</h2><p class="muted">🛡️ Moderators</p></div>
    </div>
    <div class="card">
      <h2>👥 User Roles & Management</h2>
      <table><tr><th>User</th><th>Role</th><th>Credits</th><th>Actions</th></tr>
      {% for u in users %}<tr>
        <td>@{{ u.username }} {% if u.is_verified %}<span class="badge blue">✓</span>{% endif %}</td>
        <td>{% if u.is_developer %}<span class="badge blue">👑 DEVELOPER</span>{% elif u.is_moderator %}<span class="badge mod">🛡️ MOD</span>{% else %}Member{% endif %}</td>
        <td>{% if is_rick_owner(u) %}∞ Unlimited{% else %}{{ "%.2f"|format(u.net_credits) }}{% endif %}</td>
        <td>{% if u.id != current_user.id %}
          <div class="actions">
          <form method="post" action="{{ url_for('toggle_developer', user_id=u.id) }}"><button class="btn blue">{% if u.is_developer %}Remove Dev{% else %}👑 Make Dev (+120){% endif %}</button></form>
          <form method="post" action="{{ url_for('toggle_moderator', user_id=u.id) }}"><button class="btn purple">{% if u.is_moderator %}Remove Mod{% else %}🛡️ Make Mod (+90){% endif %}</button></form>
          <form method="post" action="{{ url_for('award_credits', user_id=u.id) }}" class="award-form">
            <input type="number" step="0.01" min="0.01" name="credits" placeholder="Credits" required>
            <button class="btn green">🪙 Award</button>
          </form>
          <form method="post" action="{{ url_for('developer_delete_user', user_id=u.id) }}" onsubmit="return confirm('Delete this account?')"><button class="btn red">🗑️ Delete</button></form>
          </div>
        {% else %}<span class="muted">Owner account</span>{% endif %}</td>
      </tr>{% endfor %}</table>
    </div>

    <div class="card">
      <h2>📁 Uploaded Files Management</h2>
      <p class="muted">As a Developer, you can remove any uploaded file from RickNet.</p>
      {% for f in files %}
        <div class="card" style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
            <div>
              <h3 style="margin-bottom:6px">📄 {{ f.title }}</h3>
              <p class="muted small" style="margin:0">
                📱 {{ f.vpn_type }} &nbsp; • &nbsp; 📶 {{ f.network }}
                &nbsp; • &nbsp; 👤 @{{ f.owner.username }}
              </p>
            </div>
            <div class="actions" style="margin-top:0">
              <a class="btn secondary" href="{{ url_for('file_detail', file_id=f.id) }}">👁️ View</a>
              <form method="post" action="{{ url_for('developer_delete_file', file_id=f.id) }}"
                    onsubmit="return confirm('Delete {{ f.title|e }}? This cannot be undone.')">
                <button class="btn red" type="submit">🗑️ Delete File</button>
              </form>
            </div>
          </div>
        </div>
      {% else %}
        <p class="muted">No uploaded files yet.</p>
      {% endfor %}
    </div>
    """
    return page(body, "Developer Panel", users=users, files=files, is_rick_owner=is_rick_owner,
                dev_count=sum(1 for u in users if u.is_developer),
                mod_count=sum(1 for u in users if u.is_moderator))


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

    if user.is_developer:
        user.is_developer = False
        flash(f"Developer status removed from {user.username}.")
    else:
        user.is_developer = True
        user.net_credits += 120
        flash(f"{user.username} is now a Developer and received 120 Net Credits.")
    db.session.commit()
    return redirect(url_for("developer_panel"))


@app.route("/developer/user/<int:user_id>/moderator", methods=["POST"])
@login_required
def toggle_moderator(user_id):
    developer_required()
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot change your own moderator role here.")
    else:
        if user.is_moderator:
            user.is_moderator = False
            flash(f"Moderator status removed from {user.username}.")
        else:
            user.is_moderator = True
            user.net_credits += 90
            flash(f"{user.username} is now a Moderator and received 90 Net Credits.")
        db.session.commit()
    return redirect(url_for("developer_panel"))


@app.route("/developer/user/<int:user_id>/award", methods=["POST"])
@login_required
def award_credits(user_id):
    developer_required()

    # Only the Rick owner can manually award arbitrary credits.
    if not is_rick_owner(current_user):
        abort(403)

    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    try:
        amount = float(request.form.get("credits", "0"))
    except ValueError:
        amount = 0

    if amount <= 0 or amount > 1000000:
        flash("Enter a valid credit amount.")
        return redirect(url_for("developer_panel"))

    # Rick's account is unlimited, so only the recipient balance is changed.
    user.net_credits += amount
    db.session.commit()
    flash(f"Awarded {amount:.2f} Net Credits to {user.username}.")
    return redirect(url_for("developer_panel"))


@app.route("/moderator")
@login_required
def moderator_panel():
    moderator_required()
    files = VPNFile.query.order_by(VPNFile.uploaded_at.desc()).all()
    body = """
    <h1>🛡️ Moderator Panel</h1>
    <div class="card"><h2>Moderate uploaded files</h2>
    {% for f in files %}<div class="card"><b>{{ f.title }}</b> — @{{ f.owner.username }}<br><span class="muted">{{ f.vpn_type }} · {{ f.network }}</span>
    <div class="actions"><form method="post" action="{{ url_for('moderator_delete_file', file_id=f.id) }}" onsubmit="return confirm('Delete this file?')"><button class="btn red">🗑️ Delete File</button></form></div></div>{% else %}<p class="muted">No files yet.</p>{% endfor %}</div>
    """
    return page(body, "Moderator Panel", files=files)


@app.route("/moderator/file/<int:file_id>/delete", methods=["POST"])
@login_required
def moderator_delete_file(file_id):
    moderator_required()
    f = db.session.get(VPNFile, file_id)
    if not f:
        abort(404)
    path = os.path.join(app.config["UPLOAD_FOLDER"], f.stored_filename)
    if os.path.exists(path):
        try: os.remove(path)
        except OSError: pass
    db.session.delete(f)
    db.session.commit()
    flash("File deleted by moderation.")
    return redirect(url_for("moderator_panel"))


@app.route("/developer/user/<int:user_id>/delete", methods=["POST"])
@login_required
def developer_delete_user(user_id):
    developer_required()
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot delete your own account from the Developer Panel.")
        return redirect(url_for("developer_panel"))

    for f in list(user.files):
        path = os.path.join(app.config["UPLOAD_FOLDER"], f.stored_filename)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"Account {username} was deleted.")
    return redirect(url_for("developer_panel"))


# -------------------- STARTUP --------------------

with app.app_context():
    db.create_all()
    # Lightweight migration for existing PostgreSQL/SQLite databases.
    try:
        with db.engine.begin() as conn:
            if db.engine.dialect.name == "postgresql":
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_moderator BOOLEAN NOT NULL DEFAULT FALSE')
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE')
                conn.exec_driver_sql('ALTER TABLE vpn_file ADD COLUMN IF NOT EXISTS host_sni VARCHAR(255)')
            elif db.engine.dialect.name == "sqlite":
                existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(user)")}
                if "is_moderator" not in existing:
                    conn.exec_driver_sql("ALTER TABLE user ADD COLUMN is_moderator BOOLEAN NOT NULL DEFAULT 0")
                if "is_verified" not in existing:
                    conn.exec_driver_sql("ALTER TABLE user ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT 0")
                existing_files = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(vpn_file)")}
                if "host_sni" not in existing_files:
                    conn.exec_driver_sql("ALTER TABLE vpn_file ADD COLUMN host_sni VARCHAR(255)")
    except Exception as e:
        print("Database migration notice:", e)

    developer_phone = os.environ.get("DEVELOPER_PHONE", "").strip()
    rick = User.query.filter(db.func.lower(User.username) == "rick").first()
    phone_owner = User.query.filter_by(phone=developer_phone).first() if developer_phone else None
    changed = False
    for owner in (rick, phone_owner):
        if owner:
            if not owner.is_developer:
                owner.is_developer = True
                changed = True
            if not owner.is_verified:
                owner.is_verified = True
                changed = True
    if changed:
        db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)
