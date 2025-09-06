from flask import render_template
from . import bp
from flask import request, jsonify, redirect, url_for, flash
import json, os

INSTANCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
STORES_JSON = os.path.join(INSTANCE_DIR, "stores.json")
SETTINGS_JSON = os.path.join(INSTANCE_DIR, "settings.json")
HOSTS_JSON = os.path.join(INSTANCE_DIR, "hosts.json")

def load_stores():
    with open(STORES_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def save_stores(data):
    with open(STORES_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_settings():
    with open(SETTINGS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def load_hosts():
    with open(HOSTS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def save_settings(data):
    with open(SETTINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@bp.route("/")
def dashboard():
    stores = load_stores()
    hosts = load_hosts()
    active_ids = {s["id"] for s in stores if s.get("is_active", True)}
    active_count = len(active_ids)
    # Count only hosts that belong to active stores
    hosts_total = sum(1 for h in hosts if h.get("store_id") in active_ids)
    metrics = {
        "stores_active": active_count,
        "hosts_total": hosts_total,
        "today_sales": 0,
        "month_sales": 0,
    }
    return render_template("dashboard.html", metrics=metrics)


@bp.route("/stores")
def stores():
    stores = load_stores()
    hosts = load_hosts()
    host_counts = {}
    for h in hosts:
        host_counts[h['store_id']] = host_counts.get(h['store_id'], 0) + 1
    return render_template("stores.html", stores=stores, host_counts=host_counts)

@bp.route("/settings", methods=["GET", "POST"])
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
            "admin_password": request.form.get("admin_password") or "password"
        }
        save_settings(data)
        flash("設定を保存しました。")
        return redirect(url_for("admin.settings"))
    s = load_settings()
    return render_template("settings.html", s=s)


@bp.route("/stores/create", methods=["POST"])
def stores_create():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    address = (data.get("address") or "").strip()
    phone = (data.get("phone") or "").strip()
    contact = (data.get("contact") or "").strip()
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


@bp.route("/stores/delete", methods=["POST"])
def stores_delete():
    data = request.get_json() or {}
    ids = data.get("ids") or []
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    ids = set(int(i) for i in ids)
    stores = [s for s in load_stores() if s["id"] not in ids]
    save_stores(stores)
    return jsonify({"ok": True, "deleted": list(ids)})


@bp.route("/stores/suspend", methods=["POST"])
def stores_suspend():
    data = request.get_json() or {}
    ids = data.get("ids") or []
    suspend = bool(data.get("suspend", True))
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    ids = set(int(i) for i in ids)
    stores = load_stores()
    for s in stores:
        if s["id"] in ids:
            s["is_active"] = not suspend and True or False
    save_stores(stores)
    return jsonify({"ok": True, "updated": list(ids), "is_active": not suspend})


@bp.route("/store/login", methods=["GET", "POST"])
def store_login():
    message = None
    if request.method == "POST":
        login_id = request.form.get("login_id") or ""
        password = request.form.get("password") or ""
        for s in load_stores():
            if s["login_id"] == login_id and s["password"] == password:
                if not s.get("is_active", True):
                    message = "この店舗は一時停止中のためログインできません。"
                else:
                    return redirect(url_for('admin.store_dashboard', store_id=s['id']))
                break
        else:
            message = "ログインIDまたはパスワードが正しくありません。"
    return render_template("store_login.html", message=message)


@bp.route("/stores/import", methods=["POST"])
def stores_import():
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "error": "no_file"}), 400
    # Parse CSV with headers: name,address,phone,contact,login_id,password,is_active(optional)
    text = file.read().decode("utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    stores = load_stores()
    existing_login_ids = {s["login_id"] for s in stores}
    next_id = (max([s["id"] for s in stores]) + 1) if stores else 1
    added = 0
    for row in reader:
        name = (row.get("name") or "").strip()
        address = (row.get("address") or "").strip()
        phone = (row.get("phone") or "").strip()
        contact = (row.get("contact") or "").strip()
        login_id = (row.get("login_id") or "").strip()
        password = (row.get("password") or "").strip()
        is_active = str(row.get("is_active", "true")).lower() not in ("0","false","no")
        if not all([name, address, phone, contact, login_id, password]):
            continue
        if login_id in existing_login_ids:
            continue
        stores.append({"id": next_id, "name": name, "address": address, "phone": phone, "contact": contact,
                       "login_id": login_id, "password": password, "is_active": is_active})
        existing_login_ids.add(login_id)
        next_id += 1
        added += 1
    save_stores(stores)
    return jsonify({"ok": True, "added": added})


@bp.route("/store/dashboard")
def store_dashboard():
    store_id = int(request.args.get("store_id", "0"))
    stores = load_stores()
    targets = [s for s in stores if s["id"] == store_id]
    if not targets:
        return redirect(url_for("admin.store_login"))
    store = targets[0]
    hosts = load_hosts()
    host_count = sum(1 for h in hosts if h.get("store_id") == store_id)
    return render_template("store_dashboard.html", store=store, host_count=host_count)
