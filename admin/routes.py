from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, make_response, abort, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps
from . import bp
import os, json, csv, io

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

def _is_hashed(val: str) -> bool:
    return isinstance(val, str) and (val.startswith("pbkdf2:") or val.startswith("scrypt:"))

def _ensure_hashed(val: str) -> str:
    # すでにハッシュならそのまま、平文ならハッシュ化
    return val if _is_hashed(val) else generate_password_hash(val or "")

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

    for k in ["name","address","phone","contact","login_id","password"]:
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
def _to_int(val, default=0):
    try:
        v = int(float(val))
        return max(v, 0)
    except Exception:
        return default
    
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

@bp.route("/store/hosts")
@store_required
def store_hosts():
    store = _store_context()
    hosts = [h for h in load_hosts() if h.get("store_id") == store["id"]]
    # 接客中判定：座席にアサインされてopen=Trueのホスト
    busy_ids = {s.get("host_id") for s in load_seats()
                if s.get("store_id")==store["id"] and s.get("open")}
    return render_template("store_hosts.html", active="hosts",
                           store=store, hosts=hosts, busy_ids=busy_ids)

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

    # 歩合（このホストの明細から再計算 or 保存された commission_total を利用）
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

@bp.route("/store/analytics")
@store_required
def store_analytics():
    store = _store_context()
    sales = [s for s in load_sales() if s.get("store_id")==store["id"]]
    # 追加：ホスト名マップ
    host_map = {h["id"]: h["name"] for h in load_hosts() if h.get("store_id")==store["id"]}
    return render_template("store_analytics.html", active="analytics",
                           store=store, sales=sales, host_map=host_map)

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
        r = _parse_rate(v)   # ← 250〜300行目あたりに置いた関数
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

# ===== ストア側：各種登録の最小API =====
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

    items = load_liquors()
    new_id = next_id(items)
    items.append({
        "id": new_id, "store_id": store["id"], "name": name,
        "sale_price": sale, "cost_price": cost, "reorder_point": reorder, "stock": stock
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

    for k in ("name","sale_price","cost_price","reorder_point","stock"):
        if k in data and data[k] is not None:
            v = data[k]
            if k in ("sale_price","cost_price","reorder_point","stock"):
                v = _to_int(v)
            target[k] = v
    save_liquors(items)
    return jsonify({"ok": True})

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
    data = request.get_json() or {}
    sid = int(data.get("seat_id", 0))
    lid = int(data.get("liquor_id", 0))
    qty = int(data.get("qty", 1))
    seats = load_seats()
    liquors = load_liquors()
    seat = next((s for s in seats if s["id"]==sid and s["store_id"]==store["id"]), None)
    liquor = next((l for l in liquors if l["id"]==lid and l["store_id"]==store["id"]), None)
    if not seat or not liquor: return jsonify({"ok":False,"error":"not_found"}), 404
    if liquor["stock"] < qty: return jsonify({"ok":False,"error":"no_stock"}), 400
    # 在庫減
    liquor["stock"] -= qty
    save_liquors(liquors)
    # 明細に追加
    seat.setdefault("items", []).append({
        "liquor_id": lid, "name": liquor["name"], "qty": qty, "unit_price": liquor["sale_price"]
    })
    save_seats(seats)
    return jsonify({"ok":True})

@bp.route("/store/ops/checkout", methods=["POST"])
@store_required
def store_ops_checkout():
    store = _store_context()
    data = request.get_json() or {}
    sid = int(data.get("seat_id", 0))
    seats = load_seats()
    seat = next((s for s in seats if s["id"]==sid and s["store_id"]==store["id"]), None)
    if not seat: return jsonify({"ok":False,"error":"not_found"}), 404
    items = seat.get("items", [])
    total = sum(it["qty"]*it["unit_price"] for it in items)

    # === ここから追加：歩合計算 ===
    commission_total = 0.0
    commission_details = []
    host_id_for_comm = seat.get("host_id") or 0
    for it in items:
        lid = it.get("liquor_id")
        rate = effective_commission_rate(store["id"], host_id_for_comm, lid)
        amount = (it["qty"] * it["unit_price"]) * rate
        commission_total += amount
        commission_details.append({
            "liquor_id": lid,
            "rate": rate,
            "amount": amount
        })
    # === 追加ここまで ===

    sale = {
        "id": next_id(load_sales()),
        "store_id": store["id"],
        "seat_label": seat.get("label"),
        "host_id": seat.get("host_id"),
        "guest_name": seat.get("guest_name"),
        "items": items,
        "total": total,
        "commission_total": commission_total,            # ← 追加
        "commission_details": commission_details,        # ← 追加
        "date": __import__("datetime").datetime.now().strftime("%Y-%m-%d"),
        "month": __import__("datetime").datetime.now().strftime("%Y-%m")
    }
    sales = load_sales()
    sales.append(sale)
    save_sales(sales)
    # 席クリア…
    seat.update({"open": False, "guest_name":"", "host_id":0, "items":[]})
    save_seats(seats)
    return jsonify({"ok":True, "total": total})