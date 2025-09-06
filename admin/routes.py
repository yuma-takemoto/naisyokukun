from flask import (
    render_template, request, jsonify, redirect, url_for, flash,
    session, make_response, g
)
from functools import wraps
from . import bp
import os, json, csv, io

# ===== JSON 永続化ファイル =====
INSTANCE_DIR   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
STORES_JSON    = os.path.join(INSTANCE_DIR, "stores.json")
HOSTS_JSON     = os.path.join(INSTANCE_DIR, "hosts.json")
SETTINGS_JSON  = os.path.join(INSTANCE_DIR, "settings.json")

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
        "contact": contact, "is_active": True, "login_id": login_id, "password": password
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

    for k in ["name","address","phone","contact","login_id","password"]:
        v = data.get(k)
        if v is not None:
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
            "contact": contact, "login_id": login_id, "password": password,
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
        "id","name","address","phone","contact","login_id","password","is_active"
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
            "admin_password": request.form.get("admin_password") or "password",
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
        if user == s.get("admin_user") and password == s.get("admin_password"):
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
    next_url = request.args.get("next") or url_for("admin.store_dashboard")

    if request.method == "POST":
        login_id = (request.form.get("login_id") or "").strip()
        password = (request.form.get("password") or "").strip()
        remember = bool(request.form.get("remember"))  # IDを記憶（パスワードは記憶しない）

        store = next((s for s in load_stores()
                      if s.get("login_id") == login_id and s.get("password") == password), None)
        if store:
            if not store.get("is_active", True):
                message = "この店舗は一時停止中のためログインできません。"
            else:
                session["store_id"] = store["id"]
                resp = redirect(url_for('admin.store_dashboard', store_id=store['id']))
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
