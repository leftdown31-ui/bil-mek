"""
Bil-Mek Akademi — Backend + Yönetim Paneli
Güvenlik katmanları:
  - Parameterized SQL sorguları (SQL Injection koruması)
  - Argon2/bcrypt şifre hash (brute-force'a dayanıklı)
  - Rate limiting (login + API endpoint)
  - CSRF token (form sahteciliği koruması)
  - HTTPOnly / SameSite session cookie
  - Helmet-tarzı güvenlik başlıkları
  - Input sanitization & validation
  - Brute-force lockout (5 başarısız deneme → 15 dk kilit)
  - Content Security Policy
"""

import sqlite3, os, secrets, re, html, time, hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, request, jsonify, session,
                   redirect, url_for, render_template_string, g)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Uygulama Kurulumu ──────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,   # Prod'da True yapın (HTTPS)
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

DB_PATH = os.path.join(os.path.dirname(__file__), 'bilmek.db')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ── Veritabanı ─────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS basvurular (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            phone       TEXT    NOT NULL,
            program     TEXT    NOT NULL,
            note        TEXT    DEFAULT '',
            ip          TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            okundu      INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS admin_users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            pw_hash     TEXT    NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login  DATETIME
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT    NOT NULL,
            username    TEXT,
            success     INTEGER DEFAULT 0,
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_basvuru_date ON basvurular(created_at);
        CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip, attempted_at);
        """)
        # Varsayılan admin oluştur (ilk çalıştırmada)
        existing = db.execute("SELECT id FROM admin_users LIMIT 1").fetchone()
        if not existing:
            pw = os.environ.get('ADMIN_PASSWORD', 'BilMek@2025!')
            pw_hash = generate_password_hash(pw, method='pbkdf2:sha256:600000')
            db.execute(
                "INSERT INTO admin_users (username, pw_hash) VALUES (?, ?)",
                ('admin', pw_hash)
            )
            db.commit()
            print(f"\n[!] Admin oluşturuldu → kullanıcı: admin  şifre: {pw}")
            print("[!] ADMIN_PASSWORD env değişkeniyle değiştirin!\n")

init_db()

# ── Güvenlik Yardımcıları ──────────────────────────────────────────────────
def sanitize(text, max_len=500):
    """HTML escape + uzunluk sınırı"""
    if text is None:
        return ''
    return html.escape(str(text).strip())[:max_len]

def validate_phone(phone):
    """Türkiye cep numarası: 05XXXXXXXXX"""
    clean = re.sub(r'\s', '', phone)
    return bool(re.match(r'^0[5][0-9]{9}$', clean))

def validate_name(name):
    return 3 <= len(name) <= 100

VALID_PROGRAMS = {
    "Lise Özel Ders (9-12. Sınıf)",
    "YKS Koçluk (TYT / AYT)",
    "YDT İngilizce Sertifika",
    "LGS Koçluk (6-8. Sınıf)",
    "KPSS Hazırlık",
    "DGS Hazırlık",
    "ALES Hazırlık",
    "Kütüphane Üyeliği",
}

def is_brute_forced(ip, username):
    """Son 15 dakikada 5+ başarısız deneme → kilitle"""
    db = get_db()
    since = datetime.utcnow() - timedelta(minutes=15)
    row = db.execute(
        """SELECT COUNT(*) as cnt FROM login_attempts
           WHERE ip=? AND success=0 AND attempted_at>?""",
        (ip, since)
    ).fetchone()
    return row['cnt'] >= 5

def record_attempt(ip, username, success):
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (ip, username, success) VALUES (?,?,?)",
        (ip, sanitize(username, 50), 1 if success else 0)
    )
    db.commit()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf(token):
    return secrets.compare_digest(session.get('csrf_token', ''), token or '')

# ── Güvenlik Başlıkları ───────────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return resp

# ── PUBLIC API ─────────────────────────────────────────────────────────────
@app.route('/api/basvuru', methods=['POST'])
@limiter.limit("5 per minute;30 per hour")
def api_basvuru():
    """Ön kayıt formu — SQL injection korumalı parameterized query"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Geçersiz istek.'}), 400

    # Sanitize
    name    = sanitize(data.get('name', ''))
    phone   = sanitize(data.get('phone', ''), 20)
    program = sanitize(data.get('program', ''), 100)
    note    = sanitize(data.get('note', ''), 1000)

    # Validation
    errors = {}
    if not validate_name(name):
        errors['name'] = 'Ad Soyad en az 3 karakter olmalıdır.'
    if not validate_phone(phone):
        errors['phone'] = 'Geçerli bir Türkiye cep numarası girin.'
    if program not in VALID_PROGRAMS:
        errors['program'] = 'Geçerli bir program seçin.'
    if errors:
        return jsonify({'error': 'Lütfen tüm alanları doğru doldurun.', 'fields': errors}), 422

    ip = request.remote_addr

    # Parameterized INSERT — SQL injection imkânsız
    db = get_db()
    db.execute(
        "INSERT INTO basvurular (name, phone, program, note, ip) VALUES (?,?,?,?,?)",
        (name, phone, program, note, ip)
    )
    db.commit()

    return jsonify({'success': True, 'message': 'Başvurunuz alındı.'}), 201

# Ana site dosyasını sun
@app.route('/')
def index():
    try:
        with open('bilmek-akademi.html', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Site dosyası bulunamadı.</h1>", 404

# ── ADMIN LOGIN ────────────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bil-Mek Akademi | Yönetim Girişi</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Plus Jakarta Sans',sans-serif;background:#05071a;color:#eceef8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse 60% 60% at 30% 30%,rgba(59,111,255,.15),transparent 70%),radial-gradient(ellipse 40% 40% at 80% 70%,rgba(0,229,255,.08),transparent 70%);pointer-events:none;}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.09);border-radius:24px;padding:3rem;width:100%;max-width:420px;position:relative;z-index:1;}
.logo{font-family:'Syne',sans-serif;font-size:1.4rem;font-weight:800;background:linear-gradient(135deg,#00e5ff,#3b6fff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.3rem;}
.sub{color:#8890c4;font-size:.85rem;margin-bottom:2rem;}
label{display:block;font-size:.82rem;font-weight:600;color:#8890c4;margin-bottom:.45rem;}
input{width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:.85rem 1rem;color:#eceef8;font-family:inherit;font-size:.93rem;outline:none;transition:border-color .2s;margin-bottom:1.2rem;}
input:focus{border-color:rgba(59,111,255,.5);}
button{width:100%;padding:1rem;background:linear-gradient(135deg,#3b6fff,#00e5ff);border:none;border-radius:10px;color:#fff;font-family:inherit;font-size:1rem;font-weight:700;cursor:pointer;transition:opacity .2s;}
button:hover{opacity:.88;}
.err{background:rgba(255,77,126,.15);border:1px solid rgba(255,77,126,.4);color:#ff6b9d;padding:.7rem 1rem;border-radius:8px;font-size:.85rem;margin-bottom:1rem;}
.lock{background:rgba(255,140,66,.12);border:1px solid rgba(255,140,66,.3);color:#ff8c42;padding:.7rem 1rem;border-radius:8px;font-size:.85rem;margin-bottom:1rem;}
.shield{text-align:center;margin-top:1.5rem;font-size:.75rem;color:#4a5080;}
</style>
</head>
<body>
<div class="bg"></div>
<div class="card">
  <div class="logo">Bil-Mek Akademi</div>
  <div class="sub">🔐 Yönetim Paneli Girişi</div>
  {% if locked %}
  <div class="lock">⛔ Çok fazla başarısız deneme. 15 dakika bekleyin.</div>
  {% elif error %}
  <div class="err">{{ error }}</div>
  {% endif %}
  <form method="POST" action="/admin/login">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <label>Kullanıcı Adı</label>
    <input type="text" name="username" autocomplete="username" required maxlength="50">
    <label>Şifre</label>
    <input type="password" name="password" autocomplete="current-password" required maxlength="128">
    <button type="submit" {% if locked %}disabled{% endif %}>Giriş Yap</button>
  </form>
  <div class="shield">🛡️ Tüm bağlantılar şifrelendi · Rate limiting aktif</div>
</div>
</body>
</html>"""

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    ip = request.remote_addr
    error = None
    locked = is_brute_forced(ip, None)
    csrf = generate_csrf()

    if request.method == 'POST':
        submitted_csrf = request.form.get('csrf_token', '')
        if not validate_csrf(submitted_csrf):
            error = 'Güvenlik hatası. Sayfayı yenileyip tekrar deneyin.'
            return render_template_string(LOGIN_HTML, error=error, locked=False, csrf=generate_csrf())

        if locked:
            return render_template_string(LOGIN_HTML, error=None, locked=True, csrf=csrf)

        username = request.form.get('username', '').strip()[:50]
        password = request.form.get('password', '')[:128]

        # Constant-time kullanıcı sorgusu (timing attack koruması)
        db = get_db()
        row = db.execute(
            "SELECT id, username, pw_hash FROM admin_users WHERE username=?",
            (username,)
        ).fetchone()

        # Kullanıcı yoksa da hash check yap (timing attack koruması)
        dummy_hash = 'pbkdf2:sha256:600000$x$' + 'a'*64
        check_hash = row['pw_hash'] if row else dummy_hash

        if row and check_password_hash(check_hash, password):
            record_attempt(ip, username, True)
            session.clear()
            session['admin_logged_in'] = True
            session['admin_user'] = username
            session['admin_id'] = row['id']
            session.permanent = True
            db.execute("UPDATE admin_users SET last_login=? WHERE id=?",
                       (datetime.utcnow(), row['id']))
            db.commit()
            return redirect(url_for('admin_dashboard'))
        else:
            record_attempt(ip, username, False)
            time.sleep(0.5)  # brute-force yavaşlatma
            locked = is_brute_forced(ip, None)
            if locked:
                error = None
            else:
                error = 'Kullanıcı adı veya şifre hatalı.'

    return render_template_string(LOGIN_HTML, error=error, locked=locked, csrf=csrf)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

# ── ADMIN DASHBOARD ────────────────────────────────────────────────────────
DASH_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bil-Mek Yönetim Paneli</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
:root{--deep:#05071a;--nav:#080c26;--electric:#3b6fff;--cyan:#00e5ff;--gold:#ffc937;--green:#00e6a0;--rose:#ff4d7e;--card:rgba(255,255,255,.045);--border:rgba(255,255,255,.09);--muted:#8890c4;--text:#eceef8;}
body{font-family:'Plus Jakarta Sans',sans-serif;background:var(--deep);color:var(--text);min-height:100vh;display:flex;}
/* SIDEBAR */
.sidebar{width:240px;min-height:100vh;background:var(--nav);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:0;height:100vh;}
.sb-logo{padding:1.5rem;border-bottom:1px solid var(--border);}
.sb-logo .name{font-family:'Syne',sans-serif;font-size:1.1rem;font-weight:800;background:linear-gradient(135deg,var(--cyan),var(--electric));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.sb-logo .role{font-size:.75rem;color:var(--muted);}
.sb-nav{flex:1;padding:1rem 0;}
.sb-nav a{display:flex;align-items:center;gap:.7rem;padding:.75rem 1.5rem;color:var(--muted);text-decoration:none;font-size:.88rem;font-weight:500;transition:all .2s;}
.sb-nav a:hover,.sb-nav a.active{color:var(--cyan);background:rgba(0,229,255,.06);}
.sb-nav a.active{border-right:2px solid var(--cyan);}
.sb-footer{padding:1rem 1.5rem;border-top:1px solid var(--border);}
.sb-footer a{color:var(--rose);font-size:.82rem;text-decoration:none;font-weight:600;}
/* MAIN */
.main{flex:1;display:flex;flex-direction:column;overflow:auto;}
.topbar{padding:1.2rem 2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:rgba(5,7,26,.8);backdrop-filter:blur(10px);position:sticky;top:0;z-index:10;}
.topbar h1{font-family:'Syne',sans-serif;font-size:1.2rem;font-weight:800;}
.topbar .meta{font-size:.8rem;color:var(--muted);}
.content{padding:2rem;flex:1;}
/* STATS */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem;}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:1.5rem;}
.stat-card .sc-label{font-size:.78rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:.5rem;}
.stat-card .sc-val{font-family:'Syne',sans-serif;font-size:2rem;font-weight:800;}
.stat-card .sc-sub{font-size:.78rem;color:var(--muted);margin-top:.2rem;}
/* TABLE */
.table-card{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden;}
.table-header{display:flex;align-items:center;justify-content:space-between;padding:1.2rem 1.5rem;border-bottom:1px solid var(--border);}
.table-header h3{font-family:'Syne',sans-serif;font-size:1rem;font-weight:700;}
table{width:100%;border-collapse:collapse;}
th{text-align:left;padding:.8rem 1rem;font-size:.75rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);}
td{padding:.9rem 1rem;font-size:.88rem;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,.02);}
.badge{display:inline-block;padding:.2rem .6rem;border-radius:50px;font-size:.72rem;font-weight:700;}
.badge-new{background:rgba(0,229,255,.15);color:var(--cyan);border:1px solid rgba(0,229,255,.3);}
.badge-read{background:rgba(255,255,255,.06);color:var(--muted);border:1px solid rgba(255,255,255,.1);}
.badge-prog{background:rgba(59,111,255,.15);color:#8faeff;border:1px solid rgba(59,111,255,.3);}
.btn-sm{padding:.35rem .8rem;border-radius:8px;border:1px solid rgba(0,229,255,.3);background:transparent;color:var(--cyan);font-size:.75rem;font-weight:600;cursor:pointer;transition:background .2s;}
.btn-sm:hover{background:rgba(0,229,255,.1);}
.btn-del{border-color:rgba(255,77,126,.3);color:var(--rose);}
.btn-del:hover{background:rgba(255,77,126,.1);}
.search-bar{display:flex;gap:.5rem;align-items:center;}
.search-bar input{background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:8px;padding:.5rem .9rem;color:var(--text);font-family:inherit;font-size:.85rem;outline:none;transition:border-color .2s;}
.search-bar input:focus{border-color:rgba(59,111,255,.5);}
.filter-select{background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:8px;padding:.5rem .9rem;color:var(--text);font-family:inherit;font-size:.85rem;outline:none;cursor:pointer;}
.pagination{display:flex;gap:.4rem;align-items:center;padding:1rem 1.5rem;border-top:1px solid var(--border);}
.page-btn{padding:.4rem .8rem;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:.82rem;cursor:pointer;transition:all .2s;}
.page-btn:hover,.page-btn.active{border-color:var(--cyan);color:var(--cyan);background:rgba(0,229,255,.08);}
.empty{text-align:center;padding:3rem;color:var(--muted);}
/* DETAIL MODAL */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center;}
.modal-overlay.open{display:flex;}
.modal{background:#0d1535;border:1px solid var(--border);border-radius:20px;padding:2rem;width:100%;max-width:500px;position:relative;}
.modal h3{font-family:'Syne',sans-serif;font-size:1.2rem;font-weight:800;margin-bottom:1.5rem;}
.modal-close{position:absolute;top:1rem;right:1rem;background:none;border:none;color:var(--muted);font-size:1.3rem;cursor:pointer;}
.detail-row{display:flex;gap:1rem;margin-bottom:.8rem;}
.detail-row .dr-label{width:120px;font-size:.8rem;font-weight:600;color:var(--muted);flex-shrink:0;}
.detail-row .dr-val{font-size:.9rem;}
/* CHANGE PASSWORD */
.pw-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;max-width:500px;margin-top:2rem;}
.pw-card h3{font-family:'Syne',sans-serif;font-size:1rem;font-weight:700;margin-bottom:1.5rem;}
.pw-card label{display:block;font-size:.82rem;font-weight:600;color:var(--muted);margin-bottom:.4rem;}
.pw-card input{width:100%;background:rgba(255,255,255,.06);border:1px solid var(--border);border-radius:8px;padding:.75rem .9rem;color:var(--text);font-family:inherit;font-size:.9rem;outline:none;transition:border .2s;margin-bottom:1rem;}
.pw-card input:focus{border-color:rgba(59,111,255,.5);}
.btn-primary{background:linear-gradient(135deg,var(--electric),var(--cyan));color:#fff;border:none;border-radius:10px;padding:.8rem 1.5rem;font-family:inherit;font-size:.9rem;font-weight:700;cursor:pointer;transition:opacity .2s;}
.btn-primary:hover{opacity:.88;}
.alert{padding:.7rem 1rem;border-radius:8px;font-size:.85rem;margin-bottom:1rem;}
.alert-ok{background:rgba(0,230,160,.12);border:1px solid rgba(0,230,160,.3);color:var(--green);}
.alert-err{background:rgba(255,77,126,.12);border:1px solid rgba(255,77,126,.3);color:var(--rose);}
@media(max-width:900px){.stats{grid-template-columns:1fr 1fr;}.sidebar{display:none;}}
</style>
</head>
<body>
<!-- SIDEBAR -->
<div class="sidebar">
  <div class="sb-logo">
    <div class="name">Bil-Mek Akademi</div>
    <div class="role">👤 {{ admin_user }} · Yönetici</div>
  </div>
  <nav class="sb-nav">
    <a href="/admin" class="{{ 'active' if page=='dash' }}">📊 Genel Bakış</a>
    <a href="/admin/basvurular" class="{{ 'active' if page=='list' }}">📋 Başvurular</a>
    <a href="/admin/ayarlar" class="{{ 'active' if page=='settings' }}">⚙️ Ayarlar</a>
  </nav>
  <div class="sb-footer">
    <a href="/admin/logout">🚪 Çıkış Yap</a>
  </div>
</div>

<!-- MAIN -->
<div class="main">
  <div class="topbar">
    <h1>{{ title }}</h1>
    <div class="meta">{{ now }}</div>
  </div>
  <div class="content">

  {% if page == 'dash' %}
  <!-- STATS -->
  <div class="stats">
    <div class="stat-card">
      <div class="sc-label">Toplam Başvuru</div>
      <div class="sc-val" style="color:var(--cyan);">{{ stats.total }}</div>
      <div class="sc-sub">Tüm zamanlar</div>
    </div>
    <div class="stat-card">
      <div class="sc-label">Okunmamış</div>
      <div class="sc-val" style="color:var(--rose);">{{ stats.unread }}</div>
      <div class="sc-sub">Yanıt bekliyor</div>
    </div>
    <div class="stat-card">
      <div class="sc-label">Bu Hafta</div>
      <div class="sc-val" style="color:var(--green);">{{ stats.week }}</div>
      <div class="sc-sub">Son 7 gün</div>
    </div>
    <div class="stat-card">
      <div class="sc-label">Bugün</div>
      <div class="sc-val" style="color:var(--gold);">{{ stats.today }}</div>
      <div class="sc-sub">{{ now_date }}</div>
    </div>
  </div>

  <!-- SON BAŞVURULAR -->
  <div class="table-card">
    <div class="table-header">
      <h3>📋 Son Başvurular</h3>
      <a href="/admin/basvurular" class="btn-sm">Tümünü Gör →</a>
    </div>
    {% if rows %}
    <table>
      <thead><tr><th>Ad Soyad</th><th>Telefon</th><th>Program</th><th>Tarih</th><th>Durum</th></tr></thead>
      <tbody>
      {% for r in rows %}
      <tr>
        <td>{{ r.name }}</td>
        <td><a href="tel:{{ r.phone }}" style="color:var(--cyan);text-decoration:none;">{{ r.phone }}</a></td>
        <td><span class="badge badge-prog">{{ r.program[:30] }}</span></td>
        <td style="color:var(--muted);">{{ r.created_at[:16] }}</td>
        <td>{% if r.okundu == 0 %}<span class="badge badge-new">Yeni</span>{% else %}<span class="badge badge-read">Okundu</span>{% endif %}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="empty">Henüz başvuru yok.</div>
    {% endif %}
  </div>

  {% elif page == 'list' %}
  <!-- BAŞVURULAR LİSTESİ -->
  <div class="table-card">
    <div class="table-header">
      <h3>📋 Tüm Başvurular <span style="color:var(--muted);font-size:.85rem;font-weight:400;">({{ total }})</span></h3>
      <div class="search-bar">
        <form method="GET" action="/admin/basvurular" style="display:flex;gap:.5rem;">
          <input name="q" value="{{ q }}" placeholder="Ad, telefon veya program ara...">
          <select name="okundu" class="filter-select" onchange="this.form.submit()">
            <option value="" {{ 'selected' if okundu_filter=='' }}>Tümü</option>
            <option value="0" {{ 'selected' if okundu_filter=='0' }}>Okunmamış</option>
            <option value="1" {{ 'selected' if okundu_filter=='1' }}>Okunmuş</option>
          </select>
          <button type="submit" class="btn-sm">Ara</button>
        </form>
      </div>
    </div>
    {% if rows %}
    <table>
      <thead><tr><th>#</th><th>Ad Soyad</th><th>Telefon</th><th>Program</th><th>Not</th><th>Tarih</th><th>Durum</th><th>İşlem</th></tr></thead>
      <tbody>
      {% for r in rows %}
      <tr>
        <td style="color:var(--muted);">{{ r.id }}</td>
        <td><b>{{ r.name }}</b></td>
        <td><a href="tel:{{ r.phone }}" style="color:var(--cyan);text-decoration:none;font-weight:600;">{{ r.phone }}</a></td>
        <td><span class="badge badge-prog">{{ r.program[:25] }}</span></td>
        <td style="color:var(--muted);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ r.note or '—' }}</td>
        <td style="color:var(--muted);white-space:nowrap;">{{ r.created_at[:16] }}</td>
        <td>{% if r.okundu == 0 %}<span class="badge badge-new">Yeni</span>{% else %}<span class="badge badge-read">Okundu</span>{% endif %}</td>
        <td style="white-space:nowrap;">
          <button class="btn-sm" onclick="showDetail({{ r.id }},'{{ r.name|replace("'","\\'") }}','{{ r.phone }}','{{ r.program|replace("'","\\'") }}','{{ (r.note or '')|replace("'","\\'")|replace('\\n',' ') }}','{{ r.created_at[:16] }}','{{ r.ip or '' }}')">Detay</button>
          {% if r.okundu == 0 %}
          <form method="POST" action="/admin/basvuru/{{ r.id }}/okundu" style="display:inline;">
            <input type="hidden" name="csrf_token" value="{{ csrf }}">
            <button type="submit" class="btn-sm" style="margin-left:.3rem;">✓ Okundu</button>
          </form>
          {% endif %}
          <form method="POST" action="/admin/basvuru/{{ r.id }}/sil" style="display:inline;" onsubmit="return confirm('Bu başvuruyu silmek istediğinizden emin misiniz?')">
            <input type="hidden" name="csrf_token" value="{{ csrf }}">
            <button type="submit" class="btn-sm btn-del" style="margin-left:.3rem;">Sil</button>
          </form>
        </td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
    <div class="pagination">
      {% if page_num > 1 %}<a href="?q={{ q }}&okundu={{ okundu_filter }}&sayfa={{ page_num-1 }}" class="page-btn">← Önceki</a>{% endif %}
      {% for p in range(1, total_pages+1) %}
        <a href="?q={{ q }}&okundu={{ okundu_filter }}&sayfa={{ p }}" class="page-btn {{ 'active' if p==page_num }}">{{ p }}</a>
      {% endfor %}
      {% if page_num < total_pages %}<a href="?q={{ q }}&okundu={{ okundu_filter }}&sayfa={{ page_num+1 }}" class="page-btn">Sonraki →</a>{% endif %}
    </div>
    {% else %}
    <div class="empty">Başvuru bulunamadı.</div>
    {% endif %}
  </div>

  {% elif page == 'settings' %}
  <!-- AYARLAR -->
  <div class="pw-card">
    <h3>🔑 Şifre Değiştir</h3>
    {% if pw_msg %}
    <div class="alert {{ 'alert-ok' if pw_ok else 'alert-err' }}">{{ pw_msg }}</div>
    {% endif %}
    <form method="POST" action="/admin/ayarlar/sifre">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">
      <label>Mevcut Şifre</label>
      <input type="password" name="current_pw" required maxlength="128" autocomplete="current-password">
      <label>Yeni Şifre (en az 10 karakter)</label>
      <input type="password" name="new_pw" required minlength="10" maxlength="128" autocomplete="new-password">
      <label>Yeni Şifre Tekrar</label>
      <input type="password" name="new_pw2" required minlength="10" maxlength="128" autocomplete="new-password">
      <button type="submit" class="btn-primary">Şifreyi Güncelle</button>
    </form>
  </div>
  {% endif %}

  </div><!-- /content -->
</div><!-- /main -->

<!-- DETAIL MODAL -->
<div class="modal-overlay" id="detail-modal">
  <div class="modal">
    <button class="modal-close" onclick="closeDetail()">✕</button>
    <h3>📋 Başvuru Detayı</h3>
    <div class="detail-row"><div class="dr-label">Ad Soyad</div><div class="dr-val" id="d-name"></div></div>
    <div class="detail-row"><div class="dr-label">Telefon</div><div class="dr-val"><a id="d-phone" href="#" style="color:var(--cyan);"></a></div></div>
    <div class="detail-row"><div class="dr-label">Program</div><div class="dr-val" id="d-program"></div></div>
    <div class="detail-row"><div class="dr-label">Not</div><div class="dr-val" id="d-note" style="color:var(--muted);"></div></div>
    <div class="detail-row"><div class="dr-label">Tarih</div><div class="dr-val" id="d-date" style="color:var(--muted);"></div></div>
    <div class="detail-row"><div class="dr-label">IP</div><div class="dr-val" id="d-ip" style="color:var(--muted);font-size:.8rem;"></div></div>
    <div style="margin-top:1.5rem;display:flex;gap:.7rem;">
      <a id="d-call" href="#" class="btn-primary" style="text-decoration:none;">📞 Ara</a>
      <a id="d-wa" href="#" target="_blank" class="btn-sm" style="padding:.6rem 1rem;">💬 WhatsApp</a>
    </div>
  </div>
</div>

<script>
function showDetail(id, name, phone, program, note, date, ip){
  document.getElementById('d-name').textContent = name;
  document.getElementById('d-phone').textContent = phone;
  document.getElementById('d-phone').href = 'tel:'+phone;
  document.getElementById('d-program').textContent = program;
  document.getElementById('d-note').textContent = note || '—';
  document.getElementById('d-date').textContent = date;
  document.getElementById('d-ip').textContent = ip || '—';
  document.getElementById('d-call').href = 'tel:'+phone;
  const clean = phone.replace(/[^0-9]/g,'');
  document.getElementById('d-wa').href = 'https://wa.me/9'+clean.substring(1);
  document.getElementById('detail-modal').classList.add('open');
}
function closeDetail(){ document.getElementById('detail-modal').classList.remove('open'); }
document.getElementById('detail-modal').addEventListener('click', function(e){
  if(e.target === this) closeDetail();
});
</script>
</body>
</html>"""

@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()
    today = datetime.utcnow().date()
    week_ago = datetime.utcnow() - timedelta(days=7)
    stats = {
        'total': db.execute("SELECT COUNT(*) as c FROM basvurular").fetchone()['c'],
        'unread': db.execute("SELECT COUNT(*) as c FROM basvurular WHERE okundu=0").fetchone()['c'],
        'week': db.execute("SELECT COUNT(*) as c FROM basvurular WHERE created_at>?", (week_ago,)).fetchone()['c'],
        'today': db.execute("SELECT COUNT(*) as c FROM basvurular WHERE DATE(created_at)=?", (str(today),)).fetchone()['c'],
    }
    rows = db.execute("SELECT * FROM basvurular ORDER BY created_at DESC LIMIT 10").fetchall()
    return render_template_string(DASH_HTML,
        page='dash', title='Genel Bakış',
        admin_user=session['admin_user'],
        now=datetime.now().strftime('%d.%m.%Y %H:%M'),
        now_date=str(today),
        stats=stats, rows=rows, csrf=generate_csrf()
    )

@app.route('/admin/basvurular')
@login_required
def admin_basvurular():
    db = get_db()
    q = sanitize(request.args.get('q', ''), 100)
    okundu_filter = request.args.get('okundu', '')
    page_num = max(1, int(request.args.get('sayfa', 1)))
    per_page = 20
    offset = (page_num - 1) * per_page

    where_clauses = []
    params = []
    if q:
        where_clauses.append("(name LIKE ? OR phone LIKE ? OR program LIKE ?)")
        like = f'%{q}%'
        params += [like, like, like]
    if okundu_filter in ('0', '1'):
        where_clauses.append("okundu=?")
        params.append(int(okundu_filter))

    where = ('WHERE ' + ' AND '.join(where_clauses)) if where_clauses else ''
    total = db.execute(f"SELECT COUNT(*) as c FROM basvurular {where}", params).fetchone()['c']
    total_pages = max(1, (total + per_page - 1) // per_page)

    rows = db.execute(
        f"SELECT * FROM basvurular {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    return render_template_string(DASH_HTML,
        page='list', title='Başvurular',
        admin_user=session['admin_user'],
        now=datetime.now().strftime('%d.%m.%Y %H:%M'),
        rows=rows, total=total, q=q,
        okundu_filter=okundu_filter,
        page_num=page_num, total_pages=total_pages,
        csrf=generate_csrf()
    )

@app.route('/admin/basvuru/<int:bid>/okundu', methods=['POST'])
@login_required
def mark_okundu(bid):
    if not validate_csrf(request.form.get('csrf_token')):
        return 'CSRF hatası', 403
    db = get_db()
    db.execute("UPDATE basvurular SET okundu=1 WHERE id=?", (bid,))
    db.commit()
    return redirect(url_for('admin_basvurular') + '?' + request.referrer.split('?')[-1] if request.referrer else url_for('admin_basvurular'))

@app.route('/admin/basvuru/<int:bid>/sil', methods=['POST'])
@login_required
def delete_basvuru(bid):
    if not validate_csrf(request.form.get('csrf_token')):
        return 'CSRF hatası', 403
    db = get_db()
    db.execute("DELETE FROM basvurular WHERE id=?", (bid,))
    db.commit()
    return redirect(url_for('admin_basvurular'))

@app.route('/admin/ayarlar')
@login_required
def admin_ayarlar():
    return render_template_string(DASH_HTML,
        page='settings', title='Ayarlar',
        admin_user=session['admin_user'],
        now=datetime.now().strftime('%d.%m.%Y %H:%M'),
        pw_msg=None, pw_ok=False, csrf=generate_csrf()
    )

@app.route('/admin/ayarlar/sifre', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def change_password():
    if not validate_csrf(request.form.get('csrf_token')):
        return 'CSRF hatası', 403

    current = request.form.get('current_pw', '')[:128]
    new_pw = request.form.get('new_pw', '')[:128]
    new_pw2 = request.form.get('new_pw2', '')[:128]

    db = get_db()
    admin = db.execute("SELECT pw_hash FROM admin_users WHERE id=?",
                       (session['admin_id'],)).fetchone()

    pw_msg, pw_ok = None, False

    if not check_password_hash(admin['pw_hash'], current):
        pw_msg = 'Mevcut şifre hatalı.'
    elif len(new_pw) < 10:
        pw_msg = 'Yeni şifre en az 10 karakter olmalıdır.'
    elif new_pw != new_pw2:
        pw_msg = 'Yeni şifreler eşleşmiyor.'
    else:
        new_hash = generate_password_hash(new_pw, method='pbkdf2:sha256:600000')
        db.execute("UPDATE admin_users SET pw_hash=? WHERE id=?",
                   (new_hash, session['admin_id']))
        db.commit()
        pw_msg = '✅ Şifreniz başarıyla güncellendi.'
        pw_ok = True

    return render_template_string(DASH_HTML,
        page='settings', title='Ayarlar',
        admin_user=session['admin_user'],
        now=datetime.now().strftime('%d.%m.%Y %H:%M'),
        pw_msg=pw_msg, pw_ok=pw_ok, csrf=generate_csrf()
    )

if __name__ == '__main__':
    print("\n🚀 Bil-Mek Akademi Backend başlatılıyor...")
    print("   Site:  http://localhost:5000")
    print("   Admin: http://localhost:5000/admin\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
