from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATABASE = "findout.db"

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=20.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            real_name TEXT NOT NULL,
            real_surname TEXT NOT NULL,
            phone_hash TEXT UNIQUE NOT NULL,
            age INTEGER NOT NULL,
            consent_given INTEGER DEFAULT 0,
            consent_date TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            surname TEXT NOT NULL,
            name_hash TEXT NOT NULL,
            surname_hash TEXT NOT NULL,
            area_hash TEXT NOT NULL,
            phone_hash TEXT UNIQUE NOT NULL,
            age INTEGER NOT NULL,
            account_linked_user_id INTEGER,
            opt_out_status INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_linked_user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            claimer_user_id INTEGER NOT NULL,
            relationship_state TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            is_public INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            stale_at TIMESTAMP,
            confirmed_at TIMESTAMP,
            removed_at TIMESTAMP,
            ended_at TIMESTAMP,
            ended_by INTEGER,
            FOREIGN KEY (subject_id) REFERENCES subjects(id),
            FOREIGN KEY (claimer_user_id) REFERENCES users(id),
            FOREIGN KEY (ended_by) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            response_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (claim_id) REFERENCES claims(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            searcher_user_id INTEGER NOT NULL,
            subject_id INTEGER,
            searched_name TEXT NOT NULL,
            searched_surname TEXT NOT NULL,
            search_type TEXT,
            searcher_context TEXT,
            result_status TEXT,
            result_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (searcher_user_id) REFERENCES users(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            claim_id INTEGER,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (claim_id) REFERENCES claims(id)
        )
    """)

    conn.commit()
    conn.close()

def hash_phone(phone):
    salt = "findout_salt_2026"
    normalized = phone.replace(" ", "").replace("-", "").strip()
    if not normalized.startswith("+"):
        if normalized.startswith("0"):
            normalized = "+27" + normalized[1:]
        else:
            normalized = "+27" + normalized
    return hashlib.sha256((normalized + salt).encode()).hexdigest()

def hash_name(name):
    return hashlib.sha256(name.lower().strip().encode()).hexdigest()

def hash_surname(surname):
    return hashlib.sha256(surname.lower().strip().encode()).hexdigest()

def hash_area(area):
    return hashlib.sha256(area.lower().strip().encode()).hexdigest()

def create_notification(user_id, notif_type, message, claim_id=None, conn=None):
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notifications (user_id, type, message, claim_id)
        VALUES (?, ?, ?, ?)
    """, (user_id, notif_type, message, claim_id))
    conn.commit()
    if should_close:
        conn.close()

def get_unread_count(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as count FROM notifications 
        WHERE user_id = ? AND is_read = 0
    """, (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result["count"] if result else 0

def get_dashboard_stats(user_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) as count FROM claims 
        WHERE status = 'mutual' AND claimer_user_id = ?
    """, (user_id,))
    active_count = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT COUNT(*) as count FROM claims 
        WHERE status = 'active' AND claimer_user_id = ?
    """, (user_id,))
    pending_count = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT COUNT(*) as count FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        WHERE c.status = 'active' AND s.account_linked_user_id = ?
    """, (user_id,))
    about_me_count = cursor.fetchone()["count"]

    three_days_ago = datetime.now() - timedelta(days=3)
    cursor.execute("""
        SELECT COUNT(*) as count FROM claims 
        WHERE status = 'denied' AND removed_at > ? 
        AND (claimer_user_id = ? OR subject_id IN (SELECT id FROM subjects WHERE account_linked_user_id = ?))
    """, (three_days_ago, user_id, user_id))
    rejected_count = cursor.fetchone()["count"]

    conn.close()
    return {
        "active": active_count,
        "pending": pending_count,
        "about_me": about_me_count,
        "rejected": rejected_count
    }

def build_result_summary(result_status, active_claims, claim_count):
    """Human-readable summary of a search result."""
    if result_status == "opted-out":
        return "Opted out of FINDOUT"
    if result_status == "no-claim":
        return "No active claims"
    if not active_claims:
        return "No active claims"
    if result_status == "conflicting":
        states = ", ".join(sorted(set(c["relationship_state"] for c in active_claims)))
        return f"Conflicting claims ({states})"
    # single active claim
    state = active_claims[0]["relationship_state"]
    if active_claims[0]["status"] == "mutual":
        return f"Confirmed: {state}"
    return f"Active claim: {state}"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        real_name = request.form["real_name"]
        real_surname = request.form["real_surname"]
        phone = request.form["phone"]
        age = int(request.form["age"])

        if age < 18:
            flash("You must be 18 or older.", "error")
            return redirect(url_for("signup"))

        phone_hash = hash_phone(phone)
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (email, password_hash, real_name, real_surname, phone_hash, age)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email, password_hash, real_name, real_surname, phone_hash, age))
            user_id = cursor.lastrowid

            cursor.execute("SELECT id FROM subjects WHERE phone_hash = ?", (phone_hash,))
            subject = cursor.fetchone()
            if subject:
                cursor.execute("""
                    UPDATE subjects 
                    SET account_linked_user_id = ?, name = ?, surname = ?, age = ?
                    WHERE id = ?
                """, (user_id, real_name, real_surname, age, subject["id"]))
            else:
                cursor.execute("""
                    INSERT INTO subjects (name, surname, name_hash, surname_hash, area_hash, phone_hash, age, account_linked_user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (real_name, real_surname, hash_name(real_name), hash_surname(real_surname),
                      hash_area("unknown"), phone_hash, age, user_id))

            conn.commit()
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email or phone already registered.", "error")
        finally:
            conn.close()

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, password_hash))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["user_name"] = f"{user['real_name']} {user['real_surname']}"
            session["consent_given"] = bool(user["consent_given"])
            flash(f"Welcome back, {user['real_name']}.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/consent", methods=["GET", "POST"])
def consent():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET consent_given = 1, consent_date = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (session["user_id"],))
        conn.commit()
        conn.close()
        session["consent_given"] = True
        flash("Thank you for confirming your consent.", "success")
        return redirect(url_for("dashboard"))

    return render_template("consent.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not session.get("consent_given"):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT consent_given FROM users WHERE id = ?", (session["user_id"],))
        user = cursor.fetchone()
        conn.close()
        if not user or not user["consent_given"]:
            return redirect(url_for("consent"))
        session["consent_given"] = True

    conn = get_db()
    cursor = conn.cursor()

    # My claims — with subject's full name
    cursor.execute("""
        SELECT c.*, s.name AS subject_name, s.surname AS subject_surname,
               s.phone_hash AS subject_phone, u.real_name AS linked_name
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        LEFT JOIN users u ON s.account_linked_user_id = u.id
        WHERE c.claimer_user_id = ? AND c.status IN ('active', 'mutual')
        ORDER BY c.created_at DESC
    """, (session["user_id"],))
    my_claims = cursor.fetchall()

    cursor.execute("SELECT id FROM subjects WHERE account_linked_user_id = ?", (session["user_id"],))
    my_subject = cursor.fetchone()

    claims_about_me = []
    if my_subject:
        cursor.execute("""
            SELECT c.*, u.real_name AS claimer_name, u.real_surname AS claimer_surname
            FROM claims c
            JOIN users u ON c.claimer_user_id = u.id
            WHERE c.subject_id = ? AND c.status = 'active'
            ORDER BY c.created_at DESC
        """, (my_subject["id"],))
        claims_about_me = cursor.fetchall()

    # Recent searches — with searched name + result summary
    cursor.execute("""
        SELECT * FROM searches
        WHERE searcher_user_id = ?
        ORDER BY created_at DESC
        LIMIT 8
    """, (session["user_id"],))
    my_searches = cursor.fetchall()

    stats = get_dashboard_stats(session["user_id"])
    unread_count = get_unread_count(session["user_id"])

    conn.close()

    highlight_claim = request.args.get("highlight_claim")

    return render_template("dashboard.html",
                           my_claims=my_claims,
                           claims_about_me=claims_about_me,
                           my_searches=my_searches,
                           stats=stats,
                           unread_count=unread_count,
                           highlight_claim=highlight_claim)

@app.route("/search", methods=["GET", "POST"])
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form["name"].strip()
        surname = request.form["surname"].strip()
        area = request.form["area"].strip()
        phone = request.form["phone"].strip()
        age = int(request.form["age"])
        context = request.form["context"].strip()
        relationship_type = request.form.get("relationship_type", "").strip()

        name_hash = hash_name(name)
        surname_hash = hash_surname(surname)
        phone_hash = hash_phone(phone)

        conn = get_db()
        cursor = conn.cursor()

        # Look up by phone hash only (privacy — no creation of ghost profiles)
        cursor.execute("SELECT * FROM subjects WHERE phone_hash = ?", (phone_hash,))
        subject = cursor.fetchone()

        if not subject:
            # No subject exists — log search, show no-claim
            result_status = "no-claim"
            clarity_score = "Medium"
            claim_strength = "N/A"
            active_claims = []
            public_claims = []
            subject_id = None
            subject = {
                "name": name, "surname": surname,
                "phone_hash": phone_hash, "age": age,
                "opt_out_status": 0, "account_linked_user_id": None,
                "id": None
            }
            cursor.execute("""
                INSERT INTO searches (searcher_user_id, subject_id, searched_name, searched_surname,
                                      search_type, searcher_context, result_status, result_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (session["user_id"], None, name, surname, relationship_type, context,
                  result_status, "No active claims"))
            conn.commit()
            conn.close()
            return render_template("results.html",
                                   subject=subject,
                                   active_claims=[],
                                   public_claims=[],
                                   result_status=result_status,
                                   clarity_score=clarity_score,
                                   claim_strength=claim_strength,
                                   claim_count=0,
                                   relationship_type=relationship_type,
                                   searched_name=name,
                                   searched_surname=surname)

        subject_id = subject["id"]

        if subject["opt_out_status"]:
            result_status = "opted-out"
            clarity_score = "N/A"
            claim_strength = "N/A"
            active_claims = []
            public_claims = []
        else:
            cursor.execute("""
                SELECT c.*, u.real_name AS claimer_name, u.real_surname AS claimer_surname
                FROM claims c
                LEFT JOIN users u ON c.claimer_user_id = u.id
                WHERE c.subject_id = ? AND c.status IN ('active', 'mutual')
                AND (c.expires_at IS NULL OR c.expires_at > ?)
                ORDER BY c.created_at DESC
            """, (subject_id, datetime.now()))
            active_claims = cursor.fetchall()

            if len(active_claims) == 0:
                result_status = "no-claim"
                clarity_score = "Medium"
                claim_strength = "N/A"
            elif subject["account_linked_user_id"]:
                result_status = "conflicting" if len(active_claims) > 1 else "active-claim"
                if len(active_claims) == 1 and any(c["confirmed_at"] for c in active_claims):
                    clarity_score = "High"
                    claim_strength = "Strong"
                elif len(active_claims) == 1:
                    clarity_score = "Medium"
                    claim_strength = "Moderate"
                else:
                    clarity_score = "Low"
                    claim_strength = "Weak"
            else:
                result_status = "active-claim"
                clarity_score = "Medium"
                claim_strength = "Moderate"

            # Public mutual claims only (both parties opted in)
            public_claims = []
            cursor.execute("""
                SELECT c.relationship_state, u.real_name AS partner_name, u.real_surname AS partner_surname,
                       c.confirmed_at
                FROM claims c
                JOIN users u ON c.claimer_user_id = u.id
                WHERE c.subject_id = ? AND c.status = 'mutual' AND c.is_public = 1
                ORDER BY c.confirmed_at DESC
            """, (subject_id,))
            public_as_subject = cursor.fetchall()
            public_claims = list(public_as_subject)

            if subject["account_linked_user_id"]:
                cursor.execute("""
                    SELECT c.relationship_state, u.real_name AS partner_name, u.real_surname AS partner_surname,
                           c.confirmed_at
                    FROM claims c
                    JOIN subjects s ON c.subject_id = s.id
                    JOIN users u ON s.account_linked_user_id = u.id
                    WHERE c.claimer_user_id = ? AND c.status = 'mutual' AND c.is_public = 1
                    ORDER BY c.confirmed_at DESC
                """, (subject["account_linked_user_id"],))
                public_as_claimer = cursor.fetchall()
                public_claims.extend(public_as_claimer)

        summary = build_result_summary(result_status, active_claims, len(active_claims))

        cursor.execute("""
            INSERT INTO searches (searcher_user_id, subject_id, searched_name, searched_surname,
                                  search_type, searcher_context, result_status, result_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session["user_id"], subject_id, name, surname, relationship_type, context,
              result_status, summary))

        conn.commit()
        conn.close()

        return render_template("results.html",
                               subject=subject,
                               active_claims=active_claims,
                               public_claims=public_claims,
                               result_status=result_status,
                               clarity_score=clarity_score,
                               claim_strength=claim_strength,
                               claim_count=len(active_claims),
                               relationship_type=relationship_type,
                               searched_name=name,
                               searched_surname=surname)

    return render_template("search.html")

@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form["name"].strip()
        surname = request.form["surname"].strip()
        area = request.form["area"].strip()
        phone = request.form["phone"].strip()
        age = int(request.form["age"])
        relationship_state = request.form["relationship_state"]

        name_hash = hash_name(name)
        surname_hash = hash_surname(surname)
        area_hash = hash_area(area)
        phone_hash = hash_phone(phone)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM subjects WHERE phone_hash = ?", (phone_hash,))
        subject = cursor.fetchone()

        if not subject:
            cursor.execute("""
                INSERT INTO subjects (name, surname, name_hash, surname_hash, area_hash, phone_hash, age)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, surname, name_hash, surname_hash, area_hash, phone_hash, age))
            subject_id = cursor.lastrowid
        else:
            subject_id = subject["id"]
            if subject["opt_out_status"]:
                flash("This person has opted out of FINDOUT. You cannot claim a relationship with them.", "error")
                conn.close()
                return redirect(url_for("dashboard"))
            # Update with latest plain name in case claimer has more accurate info
            cursor.execute("""
                UPDATE subjects SET name = ?, surname = ?, age = ?
                WHERE id = ?
            """, (name, surname, age, subject_id))

        expires_at = datetime.now() + timedelta(days=90)
        stale_at = datetime.now() + timedelta(days=60)

        cursor.execute("""
            INSERT INTO claims (subject_id, claimer_user_id, relationship_state, expires_at, stale_at)
            VALUES (?, ?, ?, ?, ?)
        """, (subject_id, session["user_id"], relationship_state, expires_at, stale_at))

        claim_id = cursor.lastrowid

        cursor.execute("SELECT account_linked_user_id FROM subjects WHERE id = ?", (subject_id,))
        sub = cursor.fetchone()
        if sub and sub["account_linked_user_id"]:
            create_notification(
                sub["account_linked_user_id"],
                "new_claim",
                f"Someone has made a {relationship_state} claim involving you. Please review and respond.",
                claim_id,
                conn=conn
            )

        conn.commit()
        conn.close()

        flash("Claim created successfully. It will be visible to searchers.", "success")
        return redirect(url_for("dashboard"))

    return render_template("claim.html")

@app.route("/respond/<int:claim_id>", methods=["POST"])
def respond(claim_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    response_type = request.form["response_type"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, s.account_linked_user_id, s.id AS subject_id, u.real_name AS claimer_name
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        JOIN users u ON c.claimer_user_id = u.id
        WHERE c.id = ?
    """, (claim_id,))
    claim = cursor.fetchone()

    if not claim or claim["account_linked_user_id"] != session["user_id"]:
        flash("You are not authorized to respond to this claim.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    if response_type == "confirm":
        cursor.execute("""
            UPDATE claims SET status = 'mutual', confirmed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (claim_id,))
        create_notification(
            claim["claimer_user_id"],
            "claim_accepted",
            f"Your {claim['relationship_state']} claim has been confirmed.",
            claim_id,
            conn=conn
        )
    elif response_type == "deny":
        cursor.execute("""
            UPDATE claims SET status = 'denied', removed_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (claim_id,))
        create_notification(
            claim["claimer_user_id"],
            "claim_rejected",
            f"Your {claim['relationship_state']} claim was not confirmed.",
            claim_id,
            conn=conn
        )
    elif response_type == "ignore":
        create_notification(
            claim["claimer_user_id"],
            "claim_ignored",
            f"Your {claim['relationship_state']} claim was ignored. It will expire in 90 days if not confirmed.",
            claim_id,
            conn=conn
        )

    cursor.execute("""
        INSERT INTO responses (claim_id, subject_id, response_type)
        VALUES (?, ?, ?)
    """, (claim_id, claim["subject_id"], response_type))

    conn.commit()
    conn.close()

    flash("Response recorded successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/claim/end/<int:claim_id>", methods=["POST"])
def end_claim(claim_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, s.account_linked_user_id 
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        WHERE c.id = ?
    """, (claim_id,))
    claim = cursor.fetchone()

    if not claim:
        flash("Claim not found.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    if claim["claimer_user_id"] != session["user_id"] and claim["account_linked_user_id"] != session["user_id"]:
        flash("You are not authorized to end this claim.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    cursor.execute("""
        UPDATE claims SET status = 'ended', ended_at = CURRENT_TIMESTAMP, ended_by = ?
        WHERE id = ?
    """, (session["user_id"], claim_id))

    other_user = claim["claimer_user_id"] if session["user_id"] == claim["account_linked_user_id"] else claim["account_linked_user_id"]
    if other_user:
        create_notification(
            other_user,
            "claim_ended",
            "A mutual relationship claim has been ended.",
            claim_id,
            conn=conn
        )

    conn.commit()
    conn.close()

    flash("Claim ended. It will be visible in ended claims for 3 days.", "success")
    return redirect(url_for("active_claims"))

@app.route("/claim/public/<int:claim_id>", methods=["POST"])
def toggle_public(claim_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, s.account_linked_user_id 
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        WHERE c.id = ?
    """, (claim_id,))
    claim = cursor.fetchone()

    if not claim or claim["status"] != "mutual":
        flash("Only mutual claims can be made public.", "error")
        conn.close()
        return redirect(url_for("active_claims"))

    if claim["claimer_user_id"] != session["user_id"] and claim["account_linked_user_id"] != session["user_id"]:
        flash("Unauthorized.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    new_status = 0 if claim["is_public"] else 1
    cursor.execute("UPDATE claims SET is_public = ? WHERE id = ?", (new_status, claim_id))
    conn.commit()
    conn.close()

    flash("Visibility updated.", "success")
    return redirect(url_for("active_claims"))

@app.route("/claim/delete/<int:claim_id>", methods=["POST"])
def delete_claim(claim_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, s.account_linked_user_id 
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        WHERE c.id = ?
    """, (claim_id,))
    claim = cursor.fetchone()

    if not claim:
        flash("Claim not found.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    can_delete = (
        claim["claimer_user_id"] == session["user_id"] or 
        claim["account_linked_user_id"] == session["user_id"]
    )

    if not can_delete:
        flash("Unauthorized.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    cursor.execute("DELETE FROM claims WHERE id = ?", (claim_id,))
    conn.commit()
    conn.close()

    flash("Claim permanently removed.", "success")
    return redirect(url_for("dashboard"))

@app.route("/active-claims")
def active_claims():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, u.real_name AS partner_name, u.real_surname AS partner_surname, 'claimer' AS role
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        JOIN users u ON s.account_linked_user_id = u.id
        WHERE c.claimer_user_id = ? AND c.status = 'mutual'
        ORDER BY c.confirmed_at DESC
    """, (session["user_id"],))
    as_claimer = cursor.fetchall()

    cursor.execute("""
        SELECT c.*, u.real_name AS partner_name, u.real_surname AS partner_surname, 'subject' AS role
        FROM claims c
        JOIN users u ON c.claimer_user_id = u.id
        JOIN subjects s ON c.subject_id = s.id
        WHERE s.account_linked_user_id = ? AND c.status = 'mutual'
        ORDER BY c.confirmed_at DESC
    """, (session["user_id"],))
    as_subject = cursor.fetchall()

    conn.close()

    highlight_claim = request.args.get("highlight_claim")

    return render_template("active_claims.html", as_claimer=as_claimer, as_subject=as_subject, highlight_claim=highlight_claim)

@app.route("/pending-claims")
def pending_claims():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, s.name AS subject_name, s.surname AS subject_surname
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        WHERE c.claimer_user_id = ? AND c.status = 'active'
        ORDER BY c.created_at DESC
    """, (session["user_id"],))
    pending = cursor.fetchall()

    conn.close()

    highlight_claim = request.args.get("highlight_claim")
    return render_template("pending_claims.html", pending=pending, highlight_claim=highlight_claim)

@app.route("/rejected-claims")
def rejected_claims():
    if "user_id" not in session:
        return redirect(url_for("login"))

    three_days_ago = datetime.now() - timedelta(days=3)
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, u.real_name AS partner_name, u.real_surname AS partner_surname
        FROM claims c
        JOIN subjects s ON c.subject_id = s.id
        LEFT JOIN users u ON s.account_linked_user_id = u.id
        WHERE c.claimer_user_id = ? AND c.status = 'denied' AND c.removed_at > ?
        ORDER BY c.removed_at DESC
    """, (session["user_id"], three_days_ago))
    rejected_as_claimer = cursor.fetchall()

    cursor.execute("""
        SELECT c.*, u.real_name AS partner_name, u.real_surname AS partner_surname
        FROM claims c
        JOIN users u ON c.claimer_user_id = u.id
        JOIN subjects s ON c.subject_id = s.id
        WHERE s.account_linked_user_id = ? AND c.status = 'denied' AND c.removed_at > ?
        ORDER BY c.removed_at DESC
    """, (session["user_id"], three_days_ago))
    rejected_as_subject = cursor.fetchall()

    conn.close()

    highlight_claim = request.args.get("highlight_claim")

    return render_template("rejected_claims.html",
                           rejected_as_claimer=rejected_as_claimer,
                           rejected_as_subject=rejected_as_subject,
                           highlight_claim=highlight_claim)

@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, (session["user_id"],))
    notifs = cursor.fetchall()

    cursor.execute("""
        UPDATE notifications SET is_read = 1 
        WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],))
    conn.commit()
    conn.close()

    return render_template("notifications.html", notifications=notifs)

@app.route("/notifications/count")
def notifications_count():
    if "user_id" not in session:
        return jsonify({"count": 0})

    count = get_unread_count(session["user_id"])
    return jsonify({"count": count})

@app.route("/opt-out", methods=["GET", "POST"])
def opt_out():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM subjects WHERE account_linked_user_id = ?", (session["user_id"],))
        subject = cursor.fetchone()

        if subject:
            cursor.execute("""
                UPDATE claims SET status = 'removed', removed_at = CURRENT_TIMESTAMP 
                WHERE subject_id = ?
            """, (subject['id'],))
            cursor.execute("UPDATE subjects SET opt_out_status = 1 WHERE id = ?", (subject["id"],))
            conn.commit()
            flash("You have opted out of FINDOUT. All claims have been removed.", "success")
        else:
            flash("No profile found to opt out.", "error")

        conn.close()
        return redirect(url_for("dashboard"))

    return render_template("opt_out.html")

@app.route("/safety-exit")
def safety_exit():
    session.clear()
    return render_template("safety_exit.html")

if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("FINDOUT v4 Server Starting...")
    print("Open your browser to: http://localhost:5000")
    print("Press CTRL+C to stop")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)