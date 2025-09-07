from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, make_response, abort, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps
from . import bp
import os, json, csv, io
from email.message import EmailMessage
import smtplib,ssl
from datetime import datetime



# ===== JSON 永続化ファイル =====
INSTANCE_DIR   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
STORES_JSON    = os.path.join(INSTANCE_DIR, "stores.json")
HOSTS_JSON     = os.path.join(INSTANCE_DIR, "hosts.json")
SETTINGS_JSON  = os.path.join(INSTANCE_DIR, "settings.json")

# ===== CSRF: トークン生成/検証 =====
def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

@bp.before_app_request
def verify_csrf():
    # 安全なメソッドは除外
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    # ヘッダー or フォームのどちらかでOK
    token_header = request.headers.get("X-CSRF-Token")
    token_form   = request.form.get("csrf_token")
    token = token_header or token_form
    if not token or token != session.get("csrf_token"):
        return abort(400, description="Bad CSRF token")

# Jinja から {{ csrf_token() }} で使えるようにする
@bp.app_context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token}

# ===== 送信ヘルパ（SMTP） =====
def _send_email(to, subject, body, *, from_name=None, from_addr=None, cc=None, bcc=None):
    """
    実メール送信。成功で True。
    - エンベロープFrom（SMTPのMAIL FROM）は smtp_from/user を使用（到達率重視）
    - 店舗の from_email は Reply-To と表示名に反映
    """
    cfg = _smtp_conf()
    if not cfg["host"]:
        print("[mail] SMTP_HOST 未設定のため送信スキップ")
        return False

    # エンベロープFrom（実際にSMTPが使う差出人）
    envelope_from = cfg["default_from"] or cfg["user"]
    if not envelope_from:
        print("[mail] 送信元アドレスが決定できません")
        return False

    # 表示用Fromヘッダ：店舗のfrom_emailがあればそれを“見た目上のFrom”に使う
    header_from_addr = (from_addr or envelope_from)
    from_header = f'{from_name} <{header_from_addr}>' if from_name else header_from_addr

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to
    if cc:
        msg["Cc"] = ", ".join(cc) if isinstance(cc, (list, tuple, set)) else str(cc)

    # 店舗のfrom_emailがあれば、返信はそこへ
    if from_addr:
        msg["Reply-To"] = from_addr
    elif cfg["reply_to"]:
        msg["Reply-To"] = cfg["reply_to"]

    msg.set_content(body)

    send_list = [to]
    if cc:
        send_list += list(cc if isinstance(cc, (list, tuple, set)) else [cc])
    if bcc:
        send_list += list(bcc if isinstance(bcc, (list, tuple, set)) else [bcc])

    try:
        if cfg["use_ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ssl.create_default_context()) as smtp:
                if cfg["user"] and cfg["password"]:
                    smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg, from_addr=envelope_from, to_addrs=send_list)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as smtp:
                smtp.ehlo()
                if cfg["use_tls"]:
                    smtp.starttls(context=ssl.create_default_context()); smtp.ehlo()
                if cfg["user"] and cfg["password"]:
                    smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg, from_addr=envelope_from, to_addrs=send_list)
        print(f"[mail] sent to {send_list} (envelope_from={envelope_from})")
        return True
    except Exception as e:
        print(f"[mail] error: {e}")
        return False


# ===== ヘルパ =====
def load_stores():
    with open(STORES_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def save_stores(data):
    with open(STORES_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_hosts():
    with open(HOSTS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def load_settings():
    with open(SETTINGS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def save_settings(data):
    with open(SETTINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _smtp_conf():
    """settings.json → .env の順でSMTP設定を読む"""
    try:
        s = load_settings()
    except Exception:
        s = {}
    host = s.get("smtp_host") or os.getenv("SMTP_HOST")
    port = int(s.get("smtp_port") or os.getenv("SMTP_PORT") or 587)
    user = s.get("smtp_user") or os.getenv("SMTP_USER")
    password = s.get("smtp_password") or os.getenv("SMTP_PASSWORD")
    use_ssl = str(s.get("smtp_use_ssl") or os.getenv("SMTP_USE_SSL") or "false").lower() in ("1","true","yes","on")
    use_tls = str(s.get("smtp_use_tls") or os.getenv("SMTP_USE_TLS") or "true").lower() in ("1","true","yes","on")
    default_from = s.get("smtp_from") or os.getenv("SMTP_FROM") or user
    reply_to = s.get("smtp_reply_to") or os.getenv("SMTP_REPLY_TO") or None
    return {
        "host": host, "port": port, "user": user, "password": password,
        "use_ssl": use_ssl, "use_tls": use_tls,
        "default_from": default_from, "reply_to": reply_to
    }


def _send_email(to, subject, body, *, from_name=None, from_addr=None, cc=None, bcc=None):
    """
    実メール送信。成功で True。
    - 送信元は from_addr（店舗の from_email）→ settings.json/.env の SMTP_FROM → SMTP_USER の順で決定。
    """
    cfg = _smtp_conf()
    if not cfg["host"]:
        print("[mail] SMTP_HOST 未設定のため送信スキップ")
        return False

    sender_addr = from_addr or cfg["default_from"]
    if not sender_addr:
        print("[mail] 送信元アドレスが決定できません")
        return False

    # From 表示（名前があれば "Name <addr>"）
    if from_name:
        from_header = f'{from_name} <{sender_addr}>'
    else:
        from_header = sender_addr

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to
    if cc:
        if isinstance(cc, (list, tuple, set)):
            msg["Cc"] = ", ".join(cc)
        else:
            msg["Cc"] = str(cc)
    if cfg["reply_to"]:
        msg["Reply-To"] = cfg["reply_to"]
    msg.set_content(body)

    send_list = [to]
    if cc:
        send_list += list(cc if isinstance(cc, (list, tuple, set)) else [cc])
    if bcc:
        send_list += list(bcc if isinstance(bcc, (list, tuple, set)) else [bcc])

    try:
        if cfg["use_ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ssl.create_default_context()) as smtp:
                if cfg["user"] and cfg["password"]:
                    smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg, from_addr=sender_addr, to_addrs=send_list)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as smtp:
                smtp.ehlo()
                if cfg["use_tls"]:
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                if cfg["user"] and cfg["password"]:
                    smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg, from_addr=sender_addr, to_addrs=send_list)
        print(f"[mail] sent to {send_list}")
        return True
    except Exception as e:
        print(f"[mail] error: {e}")
        return False


def _is_hashed(val: str) -> bool:
    return isinstance(val, str) and (val.startswith("pbkdf2:") or val.startswith("scrypt:"))

def _ensure_hashed(val: str) -> str:
    # すでにハッシュならそのまま、平文ならハッシュ化
    return val if _is_hashed(val) else generate_password_hash(val or "")

def _to_int(val, default=0):
    try:
        v = int(float(val))
        return max(v, 0)
    except Exception:
        return default

# ===== 起動時移行：平文パスワードを自動ハッシュ化 =====
def migrate_passwords():
    # 管理者
    try:
        settings = load_settings()
        admin_pw = settings.get("admin_password", "")
        if admin_pw and not _is_hashed(admin_pw):
            settings["admin_password"] = generate_password_hash(admin_pw)
            save_settings(settings)
    except Exception:
        pass
    # 店舗
    try:
        stores = load_stores()
        changed = False
        for s in stores:
            pw = s.get("password", "")
            if pw and not _is_hashed(pw):
                s["password"] = generate_password_hash(pw)
                changed = True
        if changed:
            save_stores(stores)
    except Exception:
        pass

migrate_passwords()

# ===== 管理者ログイン必須 =====
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.login", next=request.full_path))
        return f(*args, **kwargs)
    return wrapper

# ===== 店舗ログイン必須（店舗側セッション）=====
def store_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        store_id = session.get("store_id")
        if not store_id:
            return redirect(url_for("admin.store_login", next=request.full_path))
        stores = load_stores()
        store = next((s for s in stores if s["id"] == store_id), None)
        if not store or not store.get("is_active", True):
            session.pop("store_id", None)
            return redirect(url_for("admin.store_login"))
        g.current_store = store
        return f(*args, **kwargs)
    return wrapper

# ===== ダッシュボード（管理側）=====
@bp.route("/")
@admin_required
def dashboard():
    stores = load_stores()
    hosts  = load_hosts()
    active_ids = {s["id"] for s in stores if s.get("is_active", True)}
    metrics = {
        "stores_active": len(active_ids),
        "hosts_total": sum(1 for h in hosts if h.get("store_id") in active_ids),
        "today_sales": 0,
        "month_sales": 0,
    }
    return render_template("dashboard.html", metrics=metrics)

# ===== 店舗一覧（管理側）=====
@bp.route("/stores")
@admin_required
def stores():
    stores = load_stores()
    hosts  = load_hosts()
    host_counts = {}
    for h in hosts:
        host_counts[h["store_id"]] = host_counts.get(h["store_id"], 0) + 1
    return render_template("stores.html", stores=stores, host_counts=host_counts)

@bp.route("/stores/create", methods=["POST"])
@admin_required
def stores_create():
    data = request.get_json() or {}
    name     = (data.get("name") or "").strip()
    address  = (data.get("address") or "").strip()
    phone    = (data.get("phone") or "").strip()
    contact  = (data.get("contact") or "").strip()
    login_id = (data.get("login_id") or "").strip()
    password = (data.get("password") or "").strip()
    if not all([name, address, phone, contact, login_id, password]):
        return jsonify({"ok": False, "error": "missing_fields"}), 400

    stores = load_stores()
    new_id = (max([s["id"] for s in stores]) + 1) if stores else 1
    stores.append({
        "id": new_id, "name": name, "address": address, "phone": phone,
        "contact": contact, "is_active": True, "login_id": login_id, "password": _ensure_hashed(password)
    })
    save_stores(stores)
    return jsonify({"ok": True, "id": new_id})

@bp.route("/stores/update", methods=["POST"])
@admin_required
def stores_update():
    data = request.get_json() or {}
    try:
        sid = int(data.get("id"))
    except Exception:
        return jsonify({"ok": False, "error": "bad_id"}), 400

    stores = load_stores()
    target = next((s for s in stores if s["id"] == sid), None)
    if not target:
        return jsonify({"ok": False, "error": "not_found"}), 404

    for k in ["name","address","phone","contact","login_id","password","from_email"]:
        v = data.get(k)
        if v is not None:
            if k == "password":
                if v == "":  # 空欄は変更なし
                    continue
                target[k] = _ensure_hashed(v)
            else:
                target[k] = v
    save_stores(stores)
    return jsonify({"ok": True})

@bp.route("/stores/delete", methods=["POST"])
@admin_required
def stores_delete():
    data = request.get_json() or {}
    ids = set(int(i) for i in (data.get("ids") or []))
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    stores = [s for s in load_stores() if s["id"] not in ids]
    save_stores(stores)
    return jsonify({"ok": True, "deleted": list(ids)})

@bp.route("/stores/suspend", methods=["POST"])
@admin_required
def stores_suspend():
    data = request.get_json() or {}
    ids = set(int(i) for i in (data.get("ids") or []))
    suspend = bool(data.get("suspend", True))
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    stores = load_stores()
    for s in stores:
        if s["id"] in ids:
            s["is_active"] = not suspend and True or False
    save_stores(stores)
    return jsonify({"ok": True, "updated": list(ids), "is_active": not suspend})

@bp.route("/stores/import", methods=["POST"])
@admin_required
def stores_import():
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "error": "no_file"}), 400
    text = file.read().decode("utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    stores = load_stores()
    existing = {s["login_id"] for s in stores}
    next_id = (max([s["id"] for s in stores]) + 1) if stores else 1
    added = 0
    for row in reader:
        name     = (row.get("name") or "").strip()
        address  = (row.get("address") or "").strip()
        phone    = (row.get("phone") or "").strip()
        contact  = (row.get("contact") or "").strip()
        login_id = (row.get("login_id") or "").strip()
        password = (row.get("password") or "").strip()
        is_active = str(row.get("is_active", "true")).lower() not in ("0","false","no")
        if not all([name, address, phone, contact, login_id, password]): continue
        if login_id in existing: continue
        stores.append({
            "id": next_id, "name": name, "address": address, "phone": phone,
            "contact": contact, "login_id": login_id, "password": _ensure_hashed(password),
            "is_active": is_active
        })
        existing.add(login_id); next_id += 1; added += 1
    save_stores(stores)
    return jsonify({"ok": True, "added": added})

@bp.route("/stores/export")
@admin_required
def stores_export():
    stores = load_stores()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id","name","address","phone","contact","login_id","password","is_active","from_email"
    ])
    writer.writeheader()
    for s in stores: writer.writerow(s)
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=stores.csv"
    return resp

# ===== ホスト管理（管理側）=====
@bp.route("/hosts")
@admin_required
def hosts():
    stores = load_stores()
    hosts  = load_hosts()
    return render_template("hosts.html", stores=stores, hosts=hosts)

@bp.route("/hosts/create", methods=["POST"])
@admin_required
def hosts_create():
    data = request.get_json() or {}
    store_id = int(data.get("store_id", 0))
    name = (data.get("name") or "").strip()
    if not (store_id and name):
        return jsonify({"ok": False, "error": "missing"}), 400
    hosts = load_hosts()
    new_id = (max([h["id"] for h in hosts]) + 1) if hosts else 1
    hosts.append({"id": new_id, "store_id": store_id, "name": name})
    with open(HOSTS_JSON, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return jsonify({"ok": True, "id": new_id})

@bp.route("/hosts/delete", methods=["POST"])
@admin_required
def hosts_delete():
    data = request.get_json() or {}
    ids = set(int(i) for i in (data.get("ids") or []))
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    hosts = [h for h in load_hosts() if h["id"] not in ids]
    with open(HOSTS_JSON, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return jsonify({"ok": True, "deleted": list(ids)})

@bp.route("/hosts/export")
@admin_required
def hosts_export():
    hosts = load_hosts()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id","store_id","name"])
    writer.writeheader()
    for h in hosts: writer.writerow(h)
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=hosts.csv"
    return resp

# ===== 設定（管理側）=====
@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        data = {
            "default_commission_rate": float(request.form.get("default_commission_rate") or 0),
            "default_reorder_point": int(request.form.get("default_reorder_point") or 0),
            "closing_day": int(request.form.get("closing_day") or 31),
            "line_channel_access_token": request.form.get("line_channel_access_token") or "",
            "line_channel_secret": request.form.get("line_channel_secret") or "",
            "order_vendor_email": request.form.get("order_vendor_email") or "",
            "admin_user": request.form.get("admin_user") or "admin",
            # 入力を常にハッシュ保存（空なら現状維持を推奨：テンプレ側の案内で対応）
            "admin_password": _ensure_hashed(request.form.get("admin_password") or "password"),
        }
        save_settings(data)
        flash("設定を保存しました。")
        return redirect(url_for("admin.settings"))
    s = load_settings()
    return render_template("settings.html", s=s)

# ===== 管理者ログイン =====
@bp.route("/login", methods=["GET", "POST"])
def login():
    msg = None
    if request.method == "POST":
        user = request.form.get("user") or ""
        password = request.form.get("password") or ""
        s = load_settings()
        ok = False
        if user == s.get("admin_user"):
            apw = s.get("admin_password") or ""
            if _is_hashed(apw):
                ok = check_password_hash(apw, password)
            else:
                ok = (password == apw)
        if ok:
            session["admin_logged_in"] = True
            next_url = request.args.get("next") or url_for("admin.dashboard")
            return redirect(next_url)
        else:
            msg = "ユーザー名またはパスワードが違います。"
    return render_template("admin_login.html", message=msg)

@bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin.login"))

# ===== 店舗ログイン（IDのみ任意で記憶：Cookie）=====
@bp.route("/store/login", methods=["GET", "POST"])
def store_login():
    message = None

    if request.method == "POST":
        login_id = (request.form.get("login_id") or "").strip()
        password = (request.form.get("password") or "").strip()
        remember = bool(request.form.get("remember"))  # IDを記憶（パスワードは記憶しない）

        stores = load_stores()
        store = None
        for s in stores:
            if s.get("login_id") == login_id:
                spw = s.get("password") or ""
                if _is_hashed(spw):
                    if check_password_hash(spw, password):
                        store = s
                else:
                    if spw == password:
                        # 平文だったらここでハッシュに移行
                        s["password"] = generate_password_hash(password)
                        save_stores(stores)
                        store = s
                if store:
                    break

        if store:
            if not store.get("is_active", True):
                message = "この店舗は一時停止中のためログインできません。"
            else:
                session["store_id"] = store["id"]
                # nextが店舗系なら尊重、それ以外は店舗ポータル(ops)へ
                next_url = request.args.get("next") or ""
                if next_url.startswith("/admin/store/") or next_url.startswith("/store/"):
                    resp = redirect(next_url)
                else:
                    resp = redirect(url_for('admin.store_ops'))
                if remember:
                    resp.set_cookie("store_login_id", login_id, max_age=90*24*3600, httponly=False, samesite="Lax")
                else:
                    resp.delete_cookie("store_login_id")
                return resp
        else:
            message = "ログインIDまたはパスワードが正しくありません。"

    remembered_id = request.args.get("login_id") or request.cookies.get("store_login_id", "")
    return render_template("store_login.html", message=message, remembered_id=remembered_id)

# ===== 店舗ダッシュボード（店舗ログイン必須）=====
@bp.route("/store/dashboard")
@store_required
def store_dashboard():
    store = getattr(g, "current_store", None)
    if not store:
        return redirect(url_for("admin.store_login"))
    hosts = load_hosts()
    host_count = sum(1 for h in hosts if h.get("store_id") == store["id"])
    return render_template("store_dashboard.html", store=store, host_count=host_count)

# ===== 店舗ログアウト =====
@bp.route("/store/logout")
def store_logout():
    session.pop("store_id", None)
    return redirect(url_for("admin.store_login"))

# ===== 追加：ストア側データロード/保存 =====
LIQUORS_JSON   = os.path.join(INSTANCE_DIR, "liquors.json")
SEATS_JSON     = os.path.join(INSTANCE_DIR, "seats.json")
SALES_JSON     = os.path.join(INSTANCE_DIR, "sales.json")
COMM_JSON      = os.path.join(INSTANCE_DIR, "commissions.json")

def _load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        return default
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return default

def load_liquors():
    return _load_json(LIQUORS_JSON, [])

def save_liquors(data):
    with open(LIQUORS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_seats():
    return _load_json(SEATS_JSON, [])

def save_seats(data):
    with open(SEATS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_sales():
    return _load_json(SALES_JSON, [])

def save_sales(data):
    with open(SALES_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_commissions():
    return _load_json(COMM_JSON, {})

def save_commissions(data):
    with open(COMM_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# 効率のためのユーティリティ
def next_id(items):
    return (max([x["id"] for x in items]) + 1) if items else 1

def effective_commission_rate(store_id, host_id=None, liquor_id=None):
    """歩合は liquor→host→設定既定 の優先順位"""
    settings = load_settings()
    base = float(settings.get("default_commission_rate", 0))  # 例: 0.1 = 10%
    cfg = load_commissions().get(str(store_id), {})
    r_liq = cfg.get("per_liquor", {}).get(str(liquor_id)) if liquor_id else None
    r_host = cfg.get("per_host", {}).get(str(host_id)) if host_id else None
    for r in (r_liq, r_host, base):
        try:
            if r is not None:
                r = float(r)
                return r
        except Exception:
            continue
    return 0.0

def _parse_rate(val):
    try:
        s = str(val).strip().replace('%','')
        r = float(s)
        if r > 1:   # 10 や 15 はパーセントと解釈
            r = r / 100.0
        if r < 0: r = 0.0
        if r > 1: r = 1.0
        return r
    except Exception:
        return None

# ===== ストア側メニュー =====
def _store_context():
    sid = session.get("store_id")
    stores = load_stores()
    store = next((s for s in stores if s["id"] == sid), None)
    return store

@bp.route("/store")
@store_required
def store_home():
    return redirect(url_for("admin.store_ops"))

@bp.route("/store/register")
@store_required
def store_register():
    store = _store_context()
    liquors = [x for x in load_liquors() if x.get("store_id") == store["id"]]
    hosts = [h for h in load_hosts() if h.get("store_id") == store["id"]]
    commissions = load_commissions().get(str(store["id"]), {"per_host":{}, "per_liquor":{}})
    seats = [x for x in load_seats() if x.get("store_id") == store["id"]]
    return render_template("store_register.html", active="register",
                           store=store, liquors=liquors, hosts=hosts,
                           commissions=commissions, seats=seats)

@bp.route("/store/profile/update", methods=["POST"])
@store_required
def store_profile_update():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    from_email = (data.get("from_email") or "").strip()

    stores = load_stores()
    target = next((s for s in stores if s["id"] == store["id"]), None)
    if not target:
        return jsonify({"ok": False, "error": "not_found"}), 404

    target["from_email"] = from_email
    save_stores(stores)
    return jsonify({"ok": True})

@bp.route("/store/hosts")
@store_required
def store_hosts():
    store = _store_context()
    hosts = [h for h in load_hosts() if h.get("store_id") == store["id"]]
    # 接客中（席open=Trueでアサインされている）ホストID集合
    busy_ids = {
        s.get("host_id")
        for s in load_seats()
        if s.get("store_id") == store["id"] and s.get("open")
    }

    # 並び順：出勤中 True → 接客中 True → 名前（五十音）で昇順
    def sort_key(h):
        return (
            0 if h.get("on_duty") else 1,
            0 if h.get("id") in busy_ids else 1,
            (h.get("name") or "").lower(),
        )

    hosts_sorted = sorted(hosts, key=sort_key)
    return render_template(
        "store_hosts.html",
        active="hosts",
        store=store,
        hosts=hosts_sorted,
        busy_ids=busy_ids,
    )

# --- 店舗側：ホスト追加 ---
@bp.route("/store/hosts/create", methods=["POST"])
@store_required
def store_hosts_create():
    store = _store_context()
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name_required"}), 400

    hosts = load_hosts()
    new_id = next_id(hosts)
    hosts.append({
        "id": new_id,
        "store_id": store["id"],
        "name": name,
        "on_duty": bool(data.get("on_duty"))
    })
    with open(HOSTS_JSON, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return jsonify({"ok": True, "id": new_id})

# --- 店舗側：ホスト削除（選択一括）---
@bp.route("/store/hosts/delete", methods=["POST"])
@store_required
def store_hosts_delete():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    try:
        ids = {int(i) for i in (data.get("ids") or [])}
    except Exception:
        return jsonify({"ok": False, "error": "bad_ids"}), 400
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400

    # 当該店舗のホストのみ削除
    hosts = load_hosts()
    keep = [h for h in hosts if not (h.get("store_id")==store["id"] and h.get("id") in ids)]
    with open(HOSTS_JSON, "w", encoding="utf-8") as f:
        json.dump(keep, f, ensure_ascii=False, indent=2)

    # この店舗の席に紐付いていたホストIDは外す
    seats = load_seats()
    changed = False
    for s in seats:
        if s.get("store_id")==store["id"] and s.get("host_id") in ids:
            s["host_id"] = 0
            changed = True
    if changed:
        save_seats(seats)

    return jsonify({"ok": True, "deleted": list(ids)})

# --- 店舗側：出勤ステータス更新（トグル）---
@bp.route("/store/hosts/status", methods=["POST"])
@store_required
def store_hosts_status():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    try:
        host_id = int(data.get("id"))
    except Exception:
        return jsonify({"ok": False, "error": "bad_id"}), 400
    on = bool(data.get("on_duty"))

    hosts = load_hosts()
    target = next((h for h in hosts if h.get("id")==host_id and h.get("store_id")==store["id"]), None)
    if not target:
        return jsonify({"ok": False, "error": "not_found"}), 404
    target["on_duty"] = on
    with open(HOSTS_JSON, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return jsonify({"ok": True, "id": host_id, "on_duty": on})

@bp.route("/store/hosts/<int:host_id>")
@store_required
def store_host_detail(host_id):
    store = _store_context()
    # ホスト本体
    host = next((h for h in load_hosts() if h.get("id")==host_id and h.get("store_id")==store["id"]), None)
    if not host:
        return redirect(url_for('admin.store_hosts'))

    # 売上（このホストのものだけ）
    import datetime as dt
    today = dt.datetime.now().strftime("%Y-%m-%d")
    this_month = dt.datetime.now().strftime("%Y-%m")

    sales = [s for s in load_sales()
             if s.get("store_id")==store["id"] and s.get("host_id")==host_id]

    # 集計
    total_today = sum(s.get("total",0) for s in sales if s.get("date")==today)
    total_month = sum(s.get("total",0) for s in sales if (s.get("month")==this_month))

    # 歩合
    comm_today = sum(s.get("commission_total",0) for s in sales if s.get("date")==today)
    comm_month = sum(s.get("commission_total",0) for s in sales if s.get("month")==this_month)

    # 個別の上書き設定（確認用）
    comm_cfg = load_commissions().get(str(store["id"]), {"per_host":{}, "per_liquor":{}})
    host_rate = comm_cfg.get("per_host", {}).get(str(host_id))  # Noneなら既定
    return render_template("store_host_detail.html",
                           active="hosts", store=store, host=host,
                           sales=sales, total_today=total_today, total_month=total_month,
                           comm_today=comm_today, comm_month=comm_month, host_rate=host_rate)

@bp.route("/store/ops")
@store_required
def store_ops():
    store = _store_context()
    liquors = [x for x in load_liquors() if x.get("store_id") == store["id"]]
    seats = [x for x in load_seats() if x.get("store_id") == store["id"]]
    hosts = [h for h in load_hosts() if h.get("store_id") == store["id"]]
    return render_template("store_ops.html", active="ops",
                           store=store, liquors=liquors, seats=seats, hosts=hosts)

# === 在庫リアルタイム反映用：軽量ステータス ===
@bp.route("/store/liquors/status")
@store_required
def store_liquors_status():
    store = _store_context()
    liqs = [l for l in load_liquors() if l.get("store_id")==store["id"]]
    return jsonify({"ok": True, "liquors": [
        {"id": l["id"], "name": l.get("name"), "stock": int(l.get("stock") or 0), "sale_price": int(l.get("sale_price") or 0)}
        for l in liqs
    ]})

# === 店舗 各種設定（送信元メールアドレス） ===
@bp.route("/store/settings", methods=["GET","POST"])
@store_required
def store_settings_page():
    store = _store_context()
    if request.method == "POST":
        from_email = (request.form.get("from_email") or "").strip()
        stores = load_stores()
        for s in stores:
            if s["id"] == store["id"]:
                s["from_email"] = from_email
                save_stores(stores)
                break
        store = _store_context()  # 再読込
        return render_template("store_settings.html", active="settings", store=store, saved=True)
    return render_template("store_settings.html", active="settings", store=store)

@bp.route("/store/analytics")
@store_required
def store_analytics():
    store = _store_context()
    sales = [s for s in load_sales() if s.get("store_id")==store["id"]]
    # 追加：ホスト名マップ
    host_map = {h["id"]: h["name"] for h in load_hosts() if h.get("store_id")==store["id"]}
    return render_template("store_analytics.html", active="analytics",
                           store=store, sales=sales, host_map=host_map)

# --- 請求書表示（印刷用） ---
@bp.route("/store/invoice/<int:sale_id>")
@store_required
def store_invoice(sale_id):
    store = _store_context()
    sale = next((s for s in load_sales()
                 if s.get("id")==sale_id and s.get("store_id")==store["id"]), None)
    if not sale:
        return redirect(url_for("admin.store_analytics"))
    host = next((h for h in load_hosts() if h.get("id")==sale.get("host_id")), None)
    return render_template("store_invoice.html", store=store, sale=sale, host=host)

@bp.route("/store/inventory")
@store_required
def store_inventory():
    store = _store_context()
    liquors = [x for x in load_liquors() if x.get("store_id") == store["id"]]
    return render_template("store_inventory.html", active="inventory",
                           store=store, liquors=liquors)

@bp.route("/store/commissions/save", methods=["POST"])
@store_required
def store_commissions_save():
    store = _store_context()
    data = (request.get_json() or {})
    per_host_in   = data.get("per_host") or {}
    per_liquor_in = data.get("per_liquor") or {}

    comm = load_commissions()
    sc = comm.get(str(store["id"]), {"per_host":{}, "per_liquor":{}})

    per_host = {}
    for k, v in per_host_in.items():
        r = _parse_rate(v)
        if r is not None:
            per_host[str(int(k))] = r

    per_liquor = {}
    for k, v in per_liquor_in.items():
        r = _parse_rate(v)
        if r is not None:
            per_liquor[str(int(k))] = r

    sc["per_host"] = per_host
    sc["per_liquor"] = per_liquor
    comm[str(store["id"])] = sc
    save_commissions(comm)
    return jsonify({"ok": True})

# ===== ストア側：酒類 =====
@bp.route("/store/liquors/create", methods=["POST"])
@store_required
def store_liquors_create():
    store = _store_context()
    data = request.get_json(silent=True) or request.form.to_dict() or {}

    # name は "name" でも "liquor_name" でも受ける
    name = (data.get("name") or data.get("liquor_name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name_required"}), 400

    sale = _to_int(data.get("sale_price"))
    cost = _to_int(data.get("cost_price"))
    reorder = _to_int(data.get("reorder_point"))
    stock = _to_int(data.get("stock"))
    vendor  = (data.get("vendor_email") or "").strip()
    vendor_name = (data.get("vendor_name") or "").strip()

    items = load_liquors()
    new_id = next_id(items)
    items.append({
        "id": new_id, "store_id": store["id"], "name": name,
        "sale_price": sale, "cost_price": cost, "reorder_point": reorder, "stock": stock,
        "vendor_email": vendor,
        "vendor_name": vendor_name
    })
    save_liquors(items)
    return jsonify({"ok": True, "id": new_id})

@bp.route("/store/liquors/update", methods=["POST"])
@store_required
def store_liquors_update():
    store = _store_context()
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    try:
        lid = int(data.get("id"))
    except Exception:
        return jsonify({"ok":False,"error":"id"}), 400

    items = load_liquors()
    target = next((x for x in items if x["id"]==lid and x["store_id"]==store["id"]), None)
    if not target: return jsonify({"ok":False,"error":"not_found"}), 404

    for k in ("name","sale_price","cost_price","reorder_point","stock","vendor_email","vendor_name"):
        if k in data and data[k] is not None:
            v = data[k]
            if k in ("sale_price","cost_price","reorder_point","stock"):
                v = _to_int(v)
            else:
                v = (str(v) if v is not None else "").strip()
            target[k] = v
    # まず保存して確実に反映
    save_liquors(items)
    # 必要なら在庫通知
    _maybe_notify_low_stock(store, target, items)
    return jsonify({"ok": True})

# --- 店舗側：酒類 削除（選択一括） ---
@bp.route("/store/liquors/delete", methods=["POST"])
@store_required
def store_liquors_delete():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    try:
        ids = {int(i) for i in (data.get("ids") or [])}
    except Exception:
        return jsonify({"ok": False, "error": "bad_ids"}), 400
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400

    items = load_liquors()
    keep = []
    deleted = []
    for x in items:
        if x.get("store_id") == store["id"] and int(x.get("id")) in ids:
            deleted.append(int(x.get("id")))
            continue
        keep.append(x)

    save_liquors(keep)
    return jsonify({"ok": True, "deleted": deleted})

def _maybe_notify_low_stock(store, liquor, liquors_all):
    """
    仕様：
      - 在庫が 下限(reorder_point) と **ちょうど一致した瞬間** に 1回だけ通知。
      - 在庫が 下限 を上回ったらフラグ解除（次にまた一致した瞬間に再通知）。
      - 在庫が 下限 を下回っても（<）通知はしない。
    """
    stock = int(liquor.get("stock") or 0)
    rp    = int(liquor.get("reorder_point") or 0)
    if rp <= 0:
        return False  # 閾値未設定

    # 閾値より上に戻ったら通知フラグ解除
    if stock > rp and liquor.get("low_notified"):
        liquor.pop("low_notified", None)
        liquors_all and save_liquors(liquors_all)
        return False

    # 在庫がちょうど下限になった瞬間のみ
    if stock == rp and not liquor.get("low_notified"):
        to = (liquor.get("vendor_email") or "").strip()
        if not to:
            print("[stock-mail] 酒類にメール未設定のため通知スキップ")
            return False
        to_name = (liquor.get("vendor_name") or "").strip()

        today = datetime.now().strftime("%Y-%m-%d")
        atena = f"{to_name} 様" if to_name else f"{store.get('name','店舗')} 様"
        subj = f"[発注メール] {store.get('name','')} - {liquor.get('name','不明')} 在庫下限）"
        body = (
            f"{atena} \n\n"
            f"以下の酒類が在庫下限に到達しました。\n"
            f"  商品名 : {liquor.get('name','')}\n"
            f"  在庫   : {stock}\n"
            f"  下限   : {rp}\n"
            f"  店舗名   : {store.get('name','店舗')}\n"
            f"\n"
            f"発注よろしくお願い致します。\n"
            f"（自動通知: 内職君 / {today}）\n"
        )
        from_addr = (store.get("from_email") or "").strip()
        ok = _send_email(
           to, subj, body,
           from_name=store.get("name"),
           from_addr=store.get("from_email") or None
        )
        if ok:
            liquor["low_notified"] = True
            liquors_all and save_liquors(liquors_all)
        return ok

    # stock < rp の場合は通知しない（上記仕様）
    return False

@bp.route("/store/seats/upsert", methods=["POST"])
@store_required
def store_seats_upsert():
    store = _store_context()
    data = request.get_json() or {}
    seats = load_seats()
    if "id" in data:  # 更新
        sid = int(data["id"])
        t = next((s for s in seats if s["id"]==sid and s["store_id"]==store["id"]), None)
        if not t: return jsonify({"ok":False,"error":"not_found"}), 404
        for k in ("label","open","guest_name","host_id"):
            if k in data: t[k] = data[k]
        save_seats(seats)
        return jsonify({"ok":True})
    # 新規
    new_id = next_id(seats)
    seats.append({
        "id": new_id, "store_id": store["id"],
        "label": (data.get("label") or f"席{new_id}"),
        "open": bool(data.get("open")), "guest_name": data.get("guest_name") or "",
        "host_id": int(data.get("host_id") or 0),
        "items": []  # 会計明細
    })
    save_seats(seats)
    return jsonify({"ok":True, "id": new_id})

@bp.route("/store/seats/delete", methods=["POST"])
@store_required
def store_seats_delete():
    store = _store_context()
    data = request.get_json() or {}
    ids = [int(i) for i in (data.get("ids") or []) if str(i).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    seats = load_seats()
    before = len(seats)
    seats = [s for s in seats if not (s.get("store_id")==store["id"] and s.get("id") in ids)]
    save_seats(seats)
    return jsonify({"ok": True, "deleted": len(ids), "remains": len(seats), "removed": before - len(seats)})

@bp.route("/store/ops/order", methods=["POST"])
@store_required
def store_ops_order():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    sid = int(data.get("seat_id", 0))
    lid = int(data.get("liquor_id", 0))
    try:
        qty = int(data.get("qty", 1))
    except Exception:
        qty = 1
    qty = max(1, qty)

    seats    = load_seats()
    liquors  = load_liquors()
    seat     = next((s for s in seats if s.get("id")==sid and s.get("store_id")==store["id"]), None)
    liquor   = next((l for l in liquors if l.get("id")==lid and l.get("store_id")==store["id"]), None)
    if not seat or not liquor:
        return jsonify({"ok":False,"error":"not_found"}), 404

    cur_stock = int(liquor.get("stock") or 0)
    if cur_stock < qty:
        return jsonify({"ok":False,"error":"no_stock"}), 400

    # 1) 在庫減算
    liquor["stock"] = cur_stock - qty
    save_liquors(liquors)

    # 2) 席の明細に追加
    unit_price = int(liquor.get("sale_price") or 0)
    seat.setdefault("items", []).append({
        "liquor_id": lid,
        "name": liquor.get("name"),
        "qty": qty,
        "unit_price": unit_price
    })
    save_seats(seats)

    # 3) （失敗しても注文は成功のまま）下限通知のトライ
    try:
        _maybe_notify_low_stock(store, liquor, liquors)
    except Exception as e:
        print(f"[stock-mail] notify error (ignored): {e}")

    # 4) フロントのリアルタイム反映に必要な情報を返す
    return jsonify({
        "ok": True,
        "liquor_id": lid,
        "name": liquor.get("name"),
        "unit_price": unit_price,
        "stock": liquor["stock"]
    })

@bp.route("/store/ops/checkout", methods=["POST"])
@store_required
def store_ops_checkout():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    try:
        sid = int(data.get("seat_id", 0))
    except Exception:
        return jsonify({"ok": False, "error": "bad_seat"}), 400

    seats = load_seats()
    seat = next((s for s in seats if s.get("id")==sid and s.get("store_id")==store["id"]), None)
    if not seat:
        return jsonify({"ok": False, "error": "not_found"}), 404

    items = seat.get("items") or []
    def _i(v):
        try:
            return int(float(v))
        except Exception:
            return 0

    total = 0
    safe_items = []
    for it in items:
        q  = _i(it.get("qty"))
        up = _i(it.get("unit_price"))
        total += q * up
        safe_items.append({
            "liquor_id": it.get("liquor_id"),
            "name": it.get("name"),
            "qty": q,
            "unit_price": up,
        })

    commission_total = 0.0
    commission_details = []
    host_id_for_comm = int(seat.get("host_id") or 0)
    for it in safe_items:
        lid = it.get("liquor_id")
        rate = float(effective_commission_rate(store["id"], host_id_for_comm, lid) or 0.0)
        amount = (it["qty"] * it["unit_price"]) * rate
        commission_total += amount
        commission_details.append({
            "liquor_id": lid,
            "rate": rate,
            "amount": amount
        })

    sale = {
        "id": next_id(load_sales()),
        "store_id": store["id"],
        "seat_label": seat.get("label"),
        "host_id": host_id_for_comm,
        "guest_name": seat.get("guest_name") or "",
        "items": safe_items,
        "total": total,
        "commission_total": commission_total,
        "commission_details": commission_details,
        "date": __import__("datetime").datetime.now().strftime("%Y-%m-%d"),
        "month": __import__("datetime").datetime.now().strftime("%Y-%m")
    }
    sales = load_sales()
    sales.append(sale)
    save_sales(sales)

    seat.update({"open": False, "guest_name": "", "host_id": 0, "items": []})
    save_seats(seats)

    inv_url = url_for("admin.store_invoice", sale_id=sale["id"])
    return jsonify({"ok": True, "total": total, "sale_id": sale["id"], "invoice_url": inv_url})
