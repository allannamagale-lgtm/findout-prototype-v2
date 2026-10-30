import os
import re
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, jsonify, abort, g
)
from sqlalchemy import or_, and_, func
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from config import config
from extensions import db, migrate, csrf, mail, limiter, talisman


# ============================================================
# Utilities
# ============================================================

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


PHONE_SALT = "findout_salt_2026"

def normalize_phone(phone: str) -> str:
    n = re.sub(r"[\s\-()]", "", phone.strip())
    if not n.startswith("+"):
        if n.startswith("0"):
            n = "+27" + n[1:]
        else:
            n = "+27" + n
    return n

def hash_phone(phone: str) -> str:
    return hashlib.sha256((normalize_phone(phone) + PHONE_SALT).encode()).hexdigest()

def hash_lower(value: str) -> str:
    return hashlib.sha256(value.lower().strip().encode()).hexdigest()

def hash_email(email: str) -> str:
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()

def hash_work(work: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", work.lower())
    return hashlib.sha256(normalized.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def consent_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("consent_given"):
            u = db.session.get(User, session["user_id"])
            if not u or not u.consent_given:
                return redirect(url_for("consent"))
            session["consent_given"] = True
        return f(*args, **kwargs)
    return wrapper


def log_audit(action, target_type=None, target_id=None, user_id=None):
    try:
        entry = AuditLog(
            user_id=user_id or session.get("user_id"),
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip_address=request.remote_addr if request else None,
            user_agent=(request.headers.get("User-Agent", "")[:500] if request else None),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.getLogger(__name__).warning(f"Audit log failed: {e}")


def create_notification(user_id, notif_type, message, claim_id=None):
    n = Notification(
        user_id=user_id, type=notif_type, message=message, claim_id=claim_id
    )
    db.session.add(n)
    db.session.commit()


def send_verification_email(user, token):
    from flask import current_app
    link = url_for("verify_email", token=token, _external=True)
    if current_app.config["MAIL_SERVER"]:
        try:
            from flask_mail import Message
            msg = Message(
                subject="Verify your FINDOUT account",
                recipients=[user.email],
                body=f"Welcome to FINDOUT.\n\nVerify your email:\n{link}\n\nLink expires in 24h.",
            )
            mail.send(msg)
            return True
        except Exception as e:
            current_app.logger.error(f"Mail send failed: {e}")
    print("\n" + "=" * 60)
    print(f"[DEV] Email verification link for {user.email}:")
    print(link)
    print("=" * 60 + "\n")
    return True


# ============================================================
# Models
# ============================================================

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email_hash = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    real_name = db.Column(db.String(120), nullable=False)
    real_surname = db.Column(db.String(120), nullable=False)
    phone_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    age = db.Column(db.Integer, nullable=False)
    email_verified = db.Column(db.Integer, default=0)
    consent_given = db.Column(db.Integer, default=0)
    consent_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    claims_made = db.relationship("Claim", foreign_keys="Claim.claimer_user_id", backref="claimer")


class Subject(db.Model):
    __tablename__ = "subjects"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    name_hash = db.Column(db.String(64), index=True)
    surname_hash = db.Column(db.String(64), index=True)
    area_hash = db.Column(db.String(64))
    phone_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    age = db.Column(db.Integer, nullable=False)
    email_hash = db.Column(db.String(64), index=True)
    work_hash = db.Column(db.String(64), index=True)
    account_linked_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    opt_out_status = db.Column(db.Integer, default=0, index=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    claims = db.relationship("Claim", foreign_keys="Claim.subject_id", backref="subject")


class Claim(db.Model):
    __tablename__ = "claims"
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"), nullable=False, index=True)
    claimer_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    relationship_state = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), default="active", index=True)
    is_public = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    expires_at = db.Column(db.DateTime)
    stale_at = db.Column(db.DateTime)
    confirmed_at = db.Column(db.DateTime)
    removed_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    ended_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    deleted_at = db.Column(db.DateTime, index=True)
    reports = db.relationship("Report", backref="claim")


class Response(db.Model):
    __tablename__ = "responses"
    id = db.Column(db.Integer, primary_key=True)
    claim_id = db.Column(db.Integer, db.ForeignKey("claims.id"), nullable=False, index=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"), nullable=False)
    response_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class Search(db.Model):
    __tablename__ = "searches"
    id = db.Column(db.Integer, primary_key=True)
    searcher_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"))
    searched_name = db.Column(db.String(120), nullable=False)
    searched_surname = db.Column(db.String(120), nullable=False)
    search_type = db.Column(db.String(80))
    searcher_context = db.Column(db.Text)
    result_status = db.Column(db.String(40))
    result_summary = db.Column(db.String(255))
    strength_score = db.Column(db.Float)
    strength_label = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    type = db.Column(db.String(40), nullable=False)
    message = db.Column(db.Text, nullable=False)
    claim_id = db.Column(db.Integer, db.ForeignKey("claims.id"))
    is_read = db.Column(db.Integer, default=0, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    action = db.Column(db.String(80), nullable=False, index=True)
    target_type = db.Column(db.String(40))
    target_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    reporter_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    claim_id = db.Column(db.Integer, db.ForeignKey("claims.id"), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


# ============================================================
# Strength calculator
# ============================================================

WEIGHTS = {"phone": 1.5, "email": 1.5, "full_name": 1.0, "work": 1.0, "area": 0.5, "age": 0.5}

def calculate_strength(searched: dict, subject: "Subject"):
    matched = []
    if subject is None:
        return (0.0, "N/A", [], False)
    score = 0.0
    matched.append({"field": "Phone number", "matched": True, "weight": WEIGHTS["phone"]})
    score += WEIGHTS["phone"]

    if searched.get("email"):
        if subject.email_hash and hash_email(searched["email"]) == subject.email_hash:
            matched.append({"field": "Email address", "matched": True, "weight": WEIGHTS["email"]})
            score += WEIGHTS["email"]
        else:
            matched.append({"field": "Email address", "matched": False, "weight": WEIGHTS["email"]})

    if searched.get("name") and searched.get("surname"):
        n_ok = subject.name_hash and hash_lower(searched["name"]) == subject.name_hash
        s_ok = subject.surname_hash and hash_lower(searched["surname"]) == subject.surname_hash
        if n_ok and s_ok:
            matched.append({"field": "Full name", "matched": True, "weight": WEIGHTS["full_name"]})
            score += WEIGHTS["full_name"]
        else:
            matched.append({"field": "Full name", "matched": False, "weight": WEIGHTS["full_name"]})

    if searched.get("work") and subject.work_hash:
        if hash_work(searched["work"]) == subject.work_hash:
            matched.append({"field": "Employer", "matched": True, "weight": WEIGHTS["work"]})
            score += WEIGHTS["work"]
        else:
            matched.append({"field": "Employer", "matched": False, "weight": WEIGHTS["work"]})

    if searched.get("area") and subject.area_hash:
        if hash_lower(searched["area"]) == subject.area_hash:
            matched.append({"field": "Location", "matched": True, "weight": WEIGHTS["area"]})
            score += WEIGHTS["area"]
        else:
            matched.append({"field": "Location", "matched": False, "weight": WEIGHTS["area"]})

    if searched.get("age") and subject.age:
        try:
            if abs(int(searched["age"]) - int(subject.age)) <= 2:
                matched.append({"field": "Age (±2 years)", "matched": True, "weight": WEIGHTS["age"]})
                score += WEIGHTS["age"]
            else:
                matched.append({"field": "Age (±2 years)", "matched": False, "weight": WEIGHTS["age"]})
        except (ValueError, TypeError):
            pass

    if score >= 4.0: label = "Strong"
    elif score >= 2.5: label = "Moderate"
    else: label = "Weak"

    phone_only = (score == WEIGHTS["phone"])
    return (round(score, 2), label, matched, phone_only)


def build_result_summary(result_status, active_claims):
    if result_status == "opted-out": return "Opted out of FINDOUT"
    if result_status == "no-claim" or not active_claims: return "No active claims"
    if result_status == "conflicting":
        states = ", ".join(sorted(set(c.relationship_state for c in active_claims)))
        return f"Conflicting claims ({states})"
    state = active_claims[0].relationship_state
    if active_claims[0].status == "mutual": return f"Confirmed: {state}"
    return f"Active claim: {state}"


# ============================================================
# App factory
# ============================================================

def create_app(config_name="default"):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    csp = {
        "default-src": "'self'",
        "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "connect-src": "'self'",
    }
    talisman.init_app(app, content_security_policy=csp, force_https=False,
                      session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
                      frame_options="DENY")

    os.makedirs("logs", exist_ok=True)
    handler = RotatingFileHandler("logs/findout.log", maxBytes=5_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    register_routes(app)
    register_cli(app)
    register_errors(app)

    with app.app_context():
        db.create_all()

    return app

# ============================================================
# Routes
# ============================================================

def register_routes(app):

    @app.context_processor
    def inject_globals():
        unread = 0
        if session.get("user_id"):
            unread = Notification.query.filter_by(user_id=session["user_id"], is_read=0).count()
        return {"unread_count": unread, "now": utcnow()}

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            email = request.form["email"].strip().lower()
            password = request.form["password"]
            real_name = request.form["real_name"].strip()
            real_surname = request.form["real_surname"].strip()
            phone = request.form["phone"].strip()
            try: age = int(request.form["age"])
            except ValueError:
                flash("Age must be a number.", "error")
                return redirect(url_for("signup"))

            if age < 18:
                flash("You must be 18 or older.", "error")
                return redirect(url_for("signup"))

            if User.query.filter_by(email=email).first():
                flash("Email already registered.", "error")
                return redirect(url_for("signup"))

            phone_hash = hash_phone(phone)
            if User.query.filter_by(phone_hash=phone_hash).first():
                flash("Phone already registered.", "error")
                return redirect(url_for("signup"))

            user = User(
                email=email, email_hash=hash_email(email),
                password_hash=generate_password_hash(password, method="pbkdf2:sha256:600000"),
                real_name=real_name, real_surname=real_surname,
                phone_hash=phone_hash, age=age,
            )
            db.session.add(user)
            db.session.flush()

            subject = Subject.query.filter_by(phone_hash=phone_hash).first()
            if subject:
                subject.account_linked_user_id = user.id
                subject.name = real_name
                subject.surname = real_surname
                subject.age = age
            else:
                subject = Subject(
                    name=real_name, surname=real_surname,
                    name_hash=hash_lower(real_name), surname_hash=hash_lower(real_surname),
                    area_hash=hash_lower("unknown"), phone_hash=phone_hash,
                    age=age, email_hash=hash_email(email), account_linked_user_id=user.id,
                )
                db.session.add(subject)

            db.session.commit()

            s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
            token = s.dumps(email, salt="email-verify")
            send_verification_email(user, token)

            log_audit("signup", "user", user.id, user_id=user.id)
            flash("Account created. Check the console for your verification link.", "success")
            return redirect(url_for("login"))

        return render_template("signup.html")

    @app.route("/verify/<token>")
    def verify_email(token):
        s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            email = s.loads(token, salt="email-verify", max_age=86400)
        except SignatureExpired:
            flash("Verification link expired. Please sign up again.", "error")
            return redirect(url_for("signup"))
        except BadSignature:
            flash("Invalid verification link.", "error")
            return redirect(url_for("home"))

        user = User.query.filter_by(email=email).first()
        if user:
            user.email_verified = 1
            db.session.commit()
            log_audit("email_verified", "user", user.id, user_id=user.id)
            flash("Email verified. You can now log in.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit(lambda: app.config["LOGIN_RATE_MIN"] + " per minute",
                   key_func=lambda: request.remote_addr, methods=["POST"])
    def login():
        if request.method == "POST":
            email = request.form["email"].strip().lower()
            password = request.form["password"]

            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                session.permanent = True
                session["user_id"] = user.id
                session["user_name"] = f"{user.real_name} {user.real_surname}"
                session["consent_given"] = bool(user.consent_given)
                log_audit("login", "user", user.id, user_id=user.id)
                flash(f"Welcome back, {user.real_name}.", "success")
                return redirect(url_for("dashboard"))

            log_audit("login_failed", "user", None)
            flash("Invalid email or password.", "error")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        uid = session.get("user_id")
        if uid: log_audit("logout", "user", uid, user_id=uid)
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("home"))

    # -------- Forgot & Reset Password --------
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form["email"].strip().lower()
            user = User.query.filter_by(email=email).first()
            if user:
                s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
                token = s.dumps(email, salt="password-reset")
                link = url_for("reset_password", token=token, _external=True)
                
                # Print to console for dev testing
                print("\n" + "=" * 60)
                print(f"[DEV] Password Reset Link for {email}:")
                print(link)
                print("=" * 60 + "\n")
                
                flash("If that email exists, a reset link has been printed to the server console.", "info")
            else:
                # Don't reveal if email exists (security best practice)
                flash("If that email exists, a reset link has been printed to the server console.", "info")
            return redirect(url_for("login"))
        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            email = s.loads(token, salt="password-reset", max_age=3600)
        except SignatureExpired:
            flash("Reset link expired. Please try again.", "error")
            return redirect(url_for("forgot_password"))
        except BadSignature:
            flash("Invalid reset link.", "error")
            return redirect(url_for("home"))

        if request.method == "POST":
            password = request.form["password"]
            user = User.query.filter_by(email=email).first()
            if user:
                user.password_hash = generate_password_hash(password, method="pbkdf2:sha256:600000")
                db.session.commit()
                log_audit("password_reset", "user", user.id, user_id=user.id)
                flash("Password updated. You can now log in.", "success")
                return redirect(url_for("login"))
            else:
                flash("User not found.", "error")
                return redirect(url_for("home"))

        return render_template("reset_password.html")

    @app.route("/safety-exit")
    def safety_exit():
        session.clear()
        return render_template("safety_exit.html")

    # -------- Consent --------
    @app.route("/consent", methods=["GET", "POST"])
    @login_required
    def consent():
        if request.method == "POST":
            u = db.session.get(User, session["user_id"])
            u.consent_given = 1
            u.consent_date = utcnow()
            db.session.commit()
            session["consent_given"] = True
            log_audit("consent_given", "user", u.id)
            flash("Thank you for confirming your consent.", "success")
            return redirect(url_for("dashboard"))
        return render_template("consent.html")

    # -------- Dashboard --------
    @app.route("/dashboard")
    @consent_required
    def dashboard():
        uid = session["user_id"]
        my_subject = Subject.query.filter_by(account_linked_user_id=uid).first()

        my_claims = (Claim.query.filter(Claim.claimer_user_id == uid, Claim.status.in_(["active", "mutual"]), Claim.deleted_at.is_(None))
                     .order_by(Claim.created_at.desc()).all())

        claims_about_me = []
        if my_subject:
            claims_about_me = (Claim.query.filter(Claim.subject_id == my_subject.id, Claim.status == "active", Claim.deleted_at.is_(None))
                               .order_by(Claim.created_at.desc()).all())

        my_searches = (Search.query.filter_by(searcher_user_id=uid).order_by(Search.created_at.desc()).limit(8).all())

        stats = get_dashboard_stats(uid, my_subject)
        highlight_claim = request.args.get("highlight_claim", type=int)

        return render_template("dashboard.html", my_claims=my_claims, claims_about_me=claims_about_me,
                               my_searches=my_searches, stats=stats, my_subject=my_subject, highlight_claim=highlight_claim)

    # -------- Search --------
    @app.route("/search", methods=["GET", "POST"])
    @consent_required
    @limiter.limit(lambda: app.config["SEARCH_RATE_HOUR"] + " per hour", methods=["POST"])
    @limiter.limit(lambda: app.config["SEARCH_RATE_DAY"] + " per day", methods=["POST"])
    def search():
        if request.method == "POST":
            name = request.form["name"].strip()
            surname = request.form["surname"].strip()
            area = request.form["area"].strip()
            phone = request.form["phone"].strip()
            email = request.form.get("email", "").strip()
            work = request.form.get("work", "").strip()
            context = request.form["context"].strip()
            relationship_type = request.form.get("relationship_type", "").strip()
            try: age = int(request.form["age"])
            except ValueError:
                flash("Age must be a number.", "error")
                return redirect(url_for("search"))

            phone_hash = hash_phone(phone)
            subject = Subject.query.filter_by(phone_hash=phone_hash).first()

            searched = {"name": name, "surname": surname, "area": area, "phone": phone, "email": email, "work": work, "age": age}

            if subject is None:
                result_status = "no-claim"
                active_claims, public_claims = [], []
                score, label, matched_fields, phone_only = 0.0, "N/A", [], False
                summary = "No active claims"
            elif subject.opt_out_status:
                result_status = "opted-out"
                active_claims, public_claims = [], []
                score, label, matched_fields, phone_only = 0.0, "N/A", [], False
                summary = "Opted out of FINDOUT"
            else:
                active_claims = (Claim.query.filter(Claim.subject_id == subject.id, Claim.status.in_(["active", "mutual"]),
                                                    Claim.deleted_at.is_(None), or_(Claim.expires_at.is_(None), Claim.expires_at > utcnow()))
                                 .order_by(Claim.created_at.desc()).all())

                score, label, matched_fields, phone_only = calculate_strength(searched, subject)

                if not active_claims: result_status = "no-claim"
                elif len(active_claims) > 1: result_status = "conflicting"
                else: result_status = "active-claim"

                public_claims = []
                pub_subj = (Claim.query.filter(Claim.subject_id == subject.id, Claim.status == "mutual", Claim.is_public == 1, Claim.deleted_at.is_(None)).all())
                public_claims.extend(pub_subj)
                if subject.account_linked_user_id:
                    pub_claim = (Claim.query.filter(Claim.claimer_user_id == subject.account_linked_user_id, Claim.status == "mutual", Claim.is_public == 1, Claim.deleted_at.is_(None)).all())
                    public_claims.extend(pub_claim)

                summary = build_result_summary(result_status, active_claims)

            s = Search(searcher_user_id=session["user_id"], subject_id=subject.id if subject else None,
                       searched_name=name, searched_surname=surname, search_type=relationship_type, searcher_context=context,
                       result_status=result_status, result_summary=summary, strength_score=score, strength_label=label)
            db.session.add(s)
            db.session.commit()
            log_audit("search", "subject", subject.id if subject else None)

            return render_template("results.html", subject=subject, active_claims=active_claims, public_claims=public_claims,
                                   result_status=result_status, claim_strength=label, claim_count=len(active_claims),
                                   relationship_type=relationship_type, searched_name=name, searched_surname=surname,
                                   strength_score=score, matched_fields=matched_fields, phone_only=phone_only)

        return render_template("search.html")

    # -------- Claim --------
    @app.route("/claim", methods=["GET", "POST"])
    @consent_required
    def claim():
        if request.method == "POST":
            name = request.form["name"].strip()
            surname = request.form["surname"].strip()
            area = request.form["area"].strip()
            phone = request.form["phone"].strip()
            email = request.form.get("email", "").strip()
            work = request.form.get("work", "").strip()
            relationship_state = request.form["relationship_state"]
            try: age = int(request.form["age"])
            except ValueError:
                flash("Age must be a number.", "error")
                return redirect(url_for("claim"))

            phone_hash = hash_phone(phone)
            subject = Subject.query.filter_by(phone_hash=phone_hash).first()

            if subject and subject.opt_out_status:
                flash("This person has opted out of FINDOUT.", "error")
                return redirect(url_for("dashboard"))

            if not subject:
                subject = Subject(name=name, surname=surname, name_hash=hash_lower(name), surname_hash=hash_lower(surname),
                                  area_hash=hash_lower(area), phone_hash=phone_hash, age=age,
                                  email_hash=hash_email(email) if email else None, work_hash=hash_work(work) if work else None)
                db.session.add(subject)
                db.session.flush()
            else:
                subject.name = name
                subject.surname = surname
                subject.name_hash = hash_lower(name)
                subject.surname_hash = hash_lower(surname)
                subject.area_hash = hash_lower(area)
                subject.age = age
                if email and not subject.email_hash: subject.email_hash = hash_email(email)
                if work and not subject.work_hash: subject.work_hash = hash_work(work)

            c = Claim(subject_id=subject.id, claimer_user_id=session["user_id"], relationship_state=relationship_state,
                      expires_at=utcnow() + timedelta(days=90), stale_at=utcnow() + timedelta(days=60))
            db.session.add(c)
            db.session.commit()

            if subject.account_linked_user_id:
                create_notification(subject.account_linked_user_id, "new_claim",
                                    f"Someone made a {relationship_state} claim involving you. Please review.", c.id)

            log_audit("claim_created", "claim", c.id)
            flash("Claim created. It will be visible to searchers.", "success")
            return redirect(url_for("dashboard"))

        return render_template("claim.html")

    # -------- Respond to claim --------
    @app.route("/respond/<int:claim_id>", methods=["POST"])
    @consent_required
    def respond(claim_id):
        response_type = request.form["response_type"]
        c = db.session.get(Claim, claim_id)
        if not c: abort(404)
        subject = db.session.get(Subject, c.subject_id)
        if not subject or subject.account_linked_user_id != session["user_id"]: abort(403)

        if response_type == "confirm":
            c.status = "mutual"
            c.confirmed_at = utcnow()
            create_notification(c.claimer_user_id, "claim_accepted", f"Your {c.relationship_state} claim was confirmed.", c.id)
        elif response_type == "deny":
            c.status = "denied"
            c.removed_at = utcnow()
            create_notification(c.claimer_user_id, "claim_rejected", f"Your {c.relationship_state} claim was not confirmed.", c.id)
        elif response_type == "ignore":
            create_notification(c.claimer_user_id, "claim_ignored", f"Your {c.relationship_state} claim was ignored.", c.id)

        db.session.add(Response(claim_id=c.id, subject_id=subject.id, response_type=response_type))
        db.session.commit()
        log_audit(f"claim_{response_type}", "claim", c.id)
        flash("Response recorded.", "success")
        return redirect(url_for("dashboard"))

    # -------- Report Claim --------
    @app.route("/report/<int:claim_id>", methods=["POST"])
    @consent_required
    def report_claim(claim_id):
        reason = request.form.get("reason", "Inappropriate content")
        c = db.session.get(Claim, claim_id)
        if not c: abort(404)
        
        r = Report(reporter_user_id=session["user_id"], claim_id=claim_id, reason=reason)
        db.session.add(r)
        db.session.commit()
        
        log_audit("claim_reported", "claim", claim_id)
        flash("Thank you. This claim has been reported for review.", "info")
        return redirect(request.referrer or url_for("dashboard"))

    # -------- Claim actions --------
    @app.route("/claim/end/<int:claim_id>", methods=["POST"])
    @consent_required
    def end_claim(claim_id):
        c = db.session.get(Claim, claim_id)
        if not c: abort(404)
        subject = db.session.get(Subject, c.subject_id)
        if c.claimer_user_id != session["user_id"] and (not subject or subject.account_linked_user_id != session["user_id"]): abort(403)
        c.status = "ended"
        c.ended_at = utcnow()
        c.ended_by = session["user_id"]
        other = c.claimer_user_id if session["user_id"] == (subject.account_linked_user_id if subject else None) else (subject.account_linked_user_id if subject else None)
        if other: create_notification(other, "claim_ended", "A mutual claim was ended.", c.id)
        db.session.commit()
        log_audit("claim_ended", "claim", c.id)
        flash("Claim ended.", "success")
        return redirect(url_for("active_claims"))

    @app.route("/claim/public/<int:claim_id>", methods=["POST"])
    @consent_required
    def toggle_public(claim_id):
        c = db.session.get(Claim, claim_id)
        if not c or c.status != "mutual":
            flash("Only mutual claims can be made public.", "error")
            return redirect(url_for("active_claims"))
        subject = db.session.get(Subject, c.subject_id)
        if c.claimer_user_id != session["user_id"] and (not subject or subject.account_linked_user_id != session["user_id"]): abort(403)
        c.is_public = 0 if c.is_public else 1
        db.session.commit()
        log_audit("claim_public_toggle", "claim", c.id)
        flash("Visibility updated.", "success")
        return redirect(url_for("active_claims"))

    @app.route("/claim/delete/<int:claim_id>", methods=["POST"])
    @consent_required
    def delete_claim(claim_id):
        c = db.session.get(Claim, claim_id)
        if not c: abort(404)
        subject = db.session.get(Subject, c.subject_id)
        if c.claimer_user_id != session["user_id"] and (not subject or subject.account_linked_user_id != session["user_id"]): abort(403)
        c.deleted_at = utcnow()
        c.status = "removed"
        db.session.commit()
        log_audit("claim_soft_deleted", "claim", c.id)
        flash("Claim removed.", "success")
        return redirect(url_for("dashboard"))

    # -------- Lists --------
    @app.route("/active-claims")
    @consent_required
    def active_claims():
        uid = session["user_id"]
        page = request.args.get("page", 1, type=int)
        per = app.config["ITEMS_PER_PAGE"]

        as_claimer = (Claim.query.filter_by(claimer_user_id=uid, status="mutual").filter(Claim.deleted_at.is_(None))
                      .order_by(Claim.confirmed_at.desc()).paginate(page=page, per_page=per, error_out=False))
        my_subject = Subject.query.filter_by(account_linked_user_id=uid).first()
        as_subject = []
        if my_subject:
            as_subject = (Claim.query.filter_by(subject_id=my_subject.id, status="mutual").filter(Claim.deleted_at.is_(None))
                          .order_by(Claim.confirmed_at.desc()).paginate(page=page, per_page=per, error_out=False))

        return render_template("active_claims.html", as_claimer=as_claimer, as_subject=as_subject,
                               highlight_claim=request.args.get("highlight_claim", type=int))

    @app.route("/pending-claims")
    @consent_required
    def pending_claims():
        page = request.args.get("page", 1, type=int)
        q = (Claim.query.filter_by(claimer_user_id=session["user_id"], status="active").filter(Claim.deleted_at.is_(None))
             .order_by(Claim.created_at.desc()).paginate(page=page, per_page=app.config["ITEMS_PER_PAGE"], error_out=False))
        return render_template("pending_claims.html", pending=q, highlight_claim=request.args.get("highlight_claim", type=int))

    @app.route("/rejected-claims")
    @consent_required
    def rejected_claims():
        uid = session["user_id"]
        three_days_ago = utcnow() - timedelta(days=3)
        rej_a = (Claim.query.filter_by(claimer_user_id=uid, status="denied").filter(Claim.removed_at > three_days_ago).order_by(Claim.removed_at.desc()).all())
        my_subject = Subject.query.filter_by(account_linked_user_id=uid).first()
        rej_b = []
        if my_subject:
            rej_b = (Claim.query.filter_by(subject_id=my_subject.id, status="denied").filter(Claim.removed_at > three_days_ago).order_by(Claim.removed_at.desc()).all())
        return render_template("rejected_claims.html", rejected_as_claimer=rej_a, rejected_as_subject=rej_b,
                               highlight_claim=request.args.get("highlight_claim", type=int))

    # -------- Notifications --------
    @app.route("/notifications")
    @consent_required
    def notifications():
        page = request.args.get("page", 1, type=int)
        q = (Notification.query.filter_by(user_id=session["user_id"]).order_by(Notification.created_at.desc())
             .paginate(page=page, per_page=app.config["ITEMS_PER_PAGE"], error_out=False))
        Notification.query.filter_by(user_id=session["user_id"], is_read=0).update({"is_read": 1})
        db.session.commit()
        return render_template("notifications.html", notifications=q)

    @app.route("/notifications/count")
    def notifications_count():
        if "user_id" not in session: return jsonify({"count": 0})
        n = Notification.query.filter_by(user_id=session["user_id"], is_read=0).count()
        return jsonify({"count": n})

    # -------- Opt out --------
    @app.route("/opt-out", methods=["GET", "POST"])
    @consent_required
    def opt_out():
        if request.method == "POST":
            my_subject = Subject.query.filter_by(account_linked_user_id=session["user_id"]).first()
            if my_subject:
                (Claim.query.filter_by(subject_id=my_subject.id).update({"status": "removed", "removed_at": utcnow(), "deleted_at": utcnow()}))
                my_subject.opt_out_status = 1
                db.session.commit()
                log_audit("opt_out", "subject", my_subject.id)
                flash("You have opted out of FINDOUT.", "success")
            else:
                flash("No profile found to opt out.", "error")
            return redirect(url_for("dashboard"))
        return render_template("opt_out.html")


# ============================================================
# Stats
# ============================================================

def get_dashboard_stats(user_id, my_subject):
    mutual_q = Claim.query.filter(Claim.status == "mutual", Claim.deleted_at.is_(None))
    if my_subject:
        mutual_q = mutual_q.filter(or_(Claim.claimer_user_id == user_id, Claim.subject_id == my_subject.id))
    else:
        mutual_q = mutual_q.filter(Claim.claimer_user_id == user_id)
    active_count = mutual_q.count()

    pending = Claim.query.filter_by(claimer_user_id=user_id, status="active").filter(Claim.deleted_at.is_(None)).count()

    about_me = 0
    if my_subject:
        about_me = Claim.query.filter_by(subject_id=my_subject.id, status="active").filter(Claim.deleted_at.is_(None)).count()

    three_days_ago = utcnow() - timedelta(days=3)
    rej_q = Claim.query.filter_by(status="denied").filter(Claim.removed_at > three_days_ago)
    if my_subject:
        rej_q = rej_q.filter(or_(Claim.claimer_user_id == user_id, Claim.subject_id == my_subject.id))
    else:
        rej_q = rej_q.filter(Claim.claimer_user_id == user_id)

    return {"active": active_count, "pending": pending, "about_me": about_me, "rejected": rej_q.count()}


# ============================================================
# CLI & Errors
# ============================================================

def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        with app.app_context():
            db.create_all()
            print("✓ Database initialized.")

    @app.cli.command("purge-old-data")
    def purge_old_data():
        with app.app_context():
            s_cut = utcnow() - timedelta(days=app.config["SEARCH_RETENTION_DAYS"])
            a_cut = utcnow() - timedelta(days=app.config["AUDIT_RETENTION_DAYS"])
            s_count = Search.query.filter(Search.created_at < s_cut).delete()
            a_count = AuditLog.query.filter(AuditLog.created_at < a_cut).delete()
            db.session.commit()
            print(f"✓ Purged {s_count} searches, {a_count} audit logs.")

def register_errors(app):
    @app.errorhandler(403)
    def forbidden(e): return render_template("errors/403.html"), 403
    @app.errorhandler(404)
    def not_found(e): return render_template("errors/404.html"), 404
    @app.errorhandler(429)
    def rate_limited(e): return render_template("errors/429.html"), 429
    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("500 error")
        return render_template("errors/500.html"), 500

app = create_app(os.environ.get("FLASK_ENV", "default"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("FINDOUT v5.2 — starting")
    app.run(debug=True, host="0.0.0.0", port=5000)