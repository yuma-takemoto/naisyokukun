from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, make_response, abort, g, flash, Response, stream_with_context, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps
from . import bp
import os, json, csv, io, smtplib, ssl, queue
from email.message import EmailMessage
from datetime import datetime
from collections import defaultdict
import re
import unicodedata
from werkzeug.security import check_password_hash

# ====== パス定義 ======
INSTANCE_DIR        = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
STORES_JSON         = os.path.join(INSTANCE_DIR, "stores.json")
HOSTS_JSON          = os.path.join(INSTANCE_DIR, "hosts.json")
SETTINGS_JSON       = os.path.join(INSTANCE_DIR, "settings.json")
LIQUORS_JSON        = os.path.join(INSTANCE_DIR, "liquors.json")
SEATS_JSON          = os.path.join(INSTANCE_DIR, "seats.json")
SALES_JSON          = os.path.join(INSTANCE_DIR, "sales.json")
COMM_JSON           = os.path.join(INSTANCE_DIR, "commissions.json")
CUSTOMERS_JSON      = os.path.join(INSTANCE_DIR, "customers.json")
VISITS_JSON         = os.path.join(INSTANCE_DIR, "visits.json")
BOTTLE_KEEPS_JSON   = os.path.join(INSTANCE_DIR, "bottle_keeps.json")

# ====== CSRF ======
def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.login", next=request.full_path))
        return f(*args, **kwargs)
    return wrapper

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

# この blueprint 配下のルートだけに CSRF を適用
@bp.before_request
def verify_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token_header = request.headers.get("X-CSRF-Token")
    token_form   = request.form.get("csrf_token")
    token = token_header or token_form
    if not token or token != session.get("csrf_token"):
        return abort(400, description="Bad CSRF token")

@bp.app_context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token}

# ====== JSON I/O ======
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

def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_stores():       return _load_json(STORES_JSON, [])
def save_stores(d):      _save_json(STORES_JSON, d)

def load_hosts():        return _load_json(HOSTS_JSON, [])
def save_hosts(d):       _save_json(HOSTS_JSON, d)

def load_settings():     return _load_json(SETTINGS_JSON, {})
def save_settings(d):    _save_json(SETTINGS_JSON, d)

def load_liquors():      return _load_json(LIQUORS_JSON, [])
def save_liquors(d):     _save_json(LIQUORS_JSON, d)

def load_seats():        return _load_json(SEATS_JSON, [])
def save_seats(d):       _save_json(SEATS_JSON, d)

def load_sales():        return _load_json(SALES_JSON, [])
def save_sales(d):       _save_json(SALES_JSON, d)

def load_commissions():  return _load_json(COMM_JSON, {})
def save_commissions(d): _save_json(COMM_JSON, d)

# 既存の load_customers をこの実装に差し替え（last_visit → last_visit_at フォールバック含む）
# admin/routes.py など（管理画面側のユーティリティに）
def load_customers():
    data = _load_json(CUSTOMERS_JSON, [])
    if isinstance(data, dict):
        data = list(data.values())

    out = []
    if isinstance(data, list):
        for c in data:
            if not isinstance(c, dict):
                continue
            try:
                # --- NG 複数IDの正規化 ---
                raw_ids = c.get("ng_host_ids") or c.get("ng_hosts") or []
                ng_ids = []
                if isinstance(raw_ids, list):
                    for v in raw_ids:
                        try:
                            ng_ids.append(int(v))
                        except Exception:
                            pass
                # --- 互換: 単一ID・名前配列 ---
                ng_host_id = int(c.get("ng_host_id") or 0)
                ng_host_names = c.get("ng_host_names") or []

                out.append({
                    "id": int(c.get("id") or 0),
                    "store_id": int(c.get("store_id") or 0),
                    "name": str(c.get("name") or ""),
                    "default_host_id": int(c.get("default_host_id") or 0),
                    "default_host_name": str(c.get("default_host_name") or ""),
                    "birthday": str(c.get("birthday") or ""),
                    "is_ng": bool(c.get("is_ng") or c.get("ng") or False),
                    "tags": c.get("tags") or [],
                    "memo": str(c.get("memo") or ""),
                    "keep_liquor_id": int(c.get("keep_liquor_id") or 0),
                    "keep_liquor_name": str(c.get("keep_liquor_name") or ""),
                    "keep_updated_at": str(c.get("keep_updated_at") or ""),
                    "last_visit": str(c.get("last_visit") or ""),
                    "last_visit_at": str(c.get("last_visit_at") or ""),
                    "visit_count": int(c.get("visit_count") or 0),
                    "total_amount": int(c.get("total_amount") or 0),

                    # ★NG関連（必ず返す）
                    "ng_host_ids": ng_ids,
                    "ng_host_id": ng_host_id,
                    "ng_host_names": ng_host_names,
                })
            except Exception:
                continue
    return out

def save_customers(d):   _save_json(CUSTOMERS_JSON, d)

def load_visits():       return _load_json(VISITS_JSON, [])
def save_visits(d):      _save_json(VISITS_JSON, d)

def load_bottle_keeps(): return _load_json(BOTTLE_KEEPS_JSON, [])
def save_bottle_keeps(d):_save_json(BOTTLE_KEEPS_JSON, d)

# 互換用の軽量 JSON I/O

def _json_read(path, default):
    import json, os
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default, f, ensure_ascii=False, indent=2)
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _json_write(path, data):
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _next_id(items):
    try:
        return (max([int(x.get("id", 0)) for x in items if isinstance(x, dict)]) + 1) if items else 1
    except Exception:
        return 1

def _norm_ng_ids(customer):
    """どんな保存形式でも NG を list[int] に正規化"""
    ids = set()
    raw_list = customer.get("ng_host_ids") or customer.get("ng_hosts") or []
    if isinstance(raw_list, list):
        for v in raw_list:
            try:
                ids.add(int(v))
            except Exception:
                pass
    single = customer.get("ng_host_id")  # 旧単一フィールド互換
    try:
        if single:
            ids.add(int(single))
    except Exception:
        pass
    return sorted(ids)

def _ng_names_for_customer(customer, hosts):
    """NG IDs と NG 名称の両方から、名前配列を作って返す"""
    # 1) 事前に名前で保存されているもの
    names = set()
    for nm in (customer.get("ng_host_names") or []):
        if isinstance(nm, str) and nm.strip():
            names.add(nm.strip())

    # 2) ID → ホスト名解決
    ids = _norm_ng_ids(customer)
    host_map = {}
    for h in hosts:
        try:
            hid = int(h.get("id") or 0)
            host_map[hid] = str(h.get("name") or "")
        except Exception:
            continue
    for i in ids:
        nm = host_map.get(i)
        if nm:
            names.add(nm)

    return sorted(names)

def _resolve_ng_names_for_customer(c: dict, hosts: list, store_id: int):
    """
    PC側保存形式の揺れに強く、ng_host_ids / ng_host_id / ng_host_names の
    どれが来ても名前のリストに解決して返す。
    """
    names = set()

    # 1) 明示的に名前が保存されている場合
    for nm in (c.get("ng_host_names") or []):
        try:
            s = str(nm).strip()
            if s:
                names.add(s)
        except Exception:
            pass

    # 2) IDで保存されている場合（単数/複数の両対応）
    ids = set()
    raw_ids = c.get("ng_host_ids") or []
    if isinstance(raw_ids, list):
        for v in raw_ids:
            try:
                ids.add(int(v))
            except Exception:
                pass
    one = c.get("ng_host_id")
    try:
        one = int(one or 0)
        if one:
            ids.add(one)
    except Exception:
        pass

    if ids:
        for h in (hosts or []):
            try:
                if int(h.get("store_id") or 0) == int(store_id) and int(h.get("id") or 0) in ids:
                    nm = str(h.get("name") or "").strip()
                    if nm:
                        names.add(nm)
            except Exception:
                pass

    return sorted(names)

def _settings_path():
    from pathlib import Path
    base = Path(os.path.dirname(os.path.dirname(__file__)))  # プロジェクト直下
    inst = base / "instance" / "settings.json"
    return str(inst)

def _load_settings():
    try:
        with open(_settings_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

# --- seats upsert (テンプレ互換) ---
# --- seats upsert（単票 & バッチ両対応 / 店舗スコープ）---
@bp.post("/store/seats/upsert")
@store_required
def store_seats_upsert():  # endpoint: admin.store_seats_upsert
    store = _store_context()
    payload = request.get_json(force=True, silent=True) or {}

    def _broadcast_seat(s):
        _sse_broadcast(store["id"], "seat_update", {
            "id": int(s.get("id") or 0),
            "label": s.get("label") or "",
            "open": bool(s.get("open") or False),
            "guest_name": s.get("guest_name") or "",
            "host_id": int(s.get("host_id") or 0),
            "customer_id": int(s.get("customer_id") or 0),
            "items": _seat_items_simple(s.get("items"))
        })

    # ---------- バッチモード ----------
    seats_in = None
    if isinstance(payload.get("seats"), list):
        seats_in = payload.get("seats")
    elif isinstance(payload.get("data"), list):
        seats_in = payload.get("data")

    if isinstance(seats_in, list):
        seats_all = load_seats()
        keep_others = [s for s in seats_all if int(s.get("store_id") or 0) != store["id"]]
        new_items = []
        cur_id = next_id(seats_all)

        for raw in seats_in:
            if not isinstance(raw, dict):
                continue
            sid = int(raw.get("id") or 0)
            if sid <= 0:
                sid = cur_id
                cur_id += 1
            item = {
                "id": sid,
                "store_id": store["id"],
                "label": (raw.get("label") or raw.get("name") or f"席{sid}").strip(),
                "open": bool(raw.get("open") or False),
                "guest_name": raw.get("guest_name") or "",
                "host_id": int(raw.get("host_id") or 0),
                "customer_id": int(raw.get("customer_id") or 0),
                "items": raw.get("items") or []
            }
            new_items.append(item)

        save_seats(keep_others + new_items)
        for s in new_items:
            _broadcast_seat(s)
        return jsonify({"ok": True, "count": len(new_items)}), 200

    # ---------- 単票モード（既存のOPSや“シート追加”用） ----------
    seats = load_seats()

    # 更新（id 指定あり）
    if "id" in payload and str(payload.get("id")).isdigit():
        sid = int(payload.get("id"))
        target = next((s for s in seats if s.get("id") == sid and s.get("store_id") == store["id"]), None)
        if not target:
            return jsonify({"ok": False, "error": "not_found"}), 404
        for k in ("label", "open", "guest_name", "host_id", "customer_id", "items"):
            if k in payload:
                if k in ("host_id", "customer_id"):
                    target[k] = int(payload.get(k) or 0)
                else:
                    target[k] = payload.get(k)
        save_seats(seats)
        _broadcast_seat(target)
        return jsonify({"ok": True}), 200

    # 新規（label などのみ）
    new_id_ = next_id(seats)
    item = {
        "id": new_id_,
        "store_id": store["id"],
        "label": (payload.get("label") or f"席{new_id_}").strip(),
        "open": bool(payload.get("open") or False),
        "guest_name": payload.get("guest_name") or "",
        "host_id": int(payload.get("host_id") or 0),
        "customer_id": int(payload.get("customer_id") or 0),
        "items": payload.get("items") or []
    }
    seats.append(item)
    save_seats(seats)
    _broadcast_seat(item)  # 新規でも seat_update を1発
    return jsonify({"ok": True, "id": new_id_}), 200

# --- hosts update (テンプレ互換) ---
@bp.post("/store/hosts/update")
def store_hosts_update():   # endpoint: admin.store_hosts_update
    payload = request.get_json(force=True, silent=True) or {}
    store_id = int(payload.get("store_id") or 0)
    hosts_in = payload.get("hosts") or payload.get("data") or []

    try:
        hosts_all = load_hosts()
    except Exception:
        hosts_all = _json_read(HOSTS_JSON, [])

    keep = [h for h in hosts_all if int(h.get("store_id") or 0) != store_id]
    new_items = []
    cur_id_base = _next_id(hosts_all)

    for i, raw in enumerate(hosts_in):
        if not isinstance(raw, dict):
            continue
        item = {
            "id": int(raw.get("id") or (cur_id_base + i)),
            "store_id": store_id,
            "name": str(raw.get("name") or "").strip(),
            "role": str(raw.get("role") or raw.get("title") or "host"),
            "on_duty": bool(raw.get("on_duty") or False),
            "line_user_id": str(raw.get("line_user_id") or ""),
            "last_clock_in": raw.get("last_clock_in") or "",
            "last_clock_out": raw.get("last_clock_out") or "",
        }
        new_items.append(item)

    hosts_all = keep + new_items
    try:
        save_hosts(hosts_all)
    except Exception:
        _json_write(HOSTS_JSON, hosts_all)

    return jsonify({"ok": True, "count": len(new_items)}), 200

# ====== メール送信 ======
def _smtp_conf():
    s = load_settings() or {}
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
    cfg = _smtp_conf()
    if not cfg["host"]:
        print("[mail] SMTP_HOST not set"); return False
    sender_addr = from_addr or cfg["default_from"]
    if not sender_addr:
        print("[mail] no sender"); return False
    from_header = f'{from_name} <{sender_addr}>' if from_name else sender_addr
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to
    if cc: msg["Cc"] = ", ".join(cc) if isinstance(cc, (list, tuple, set)) else str(cc)
    if cfg["reply_to"]: msg["Reply-To"] = cfg["reply_to"]
    msg.set_content(body)
    send_list = [to]
    if cc:  send_list += list(cc if isinstance(cc, (list, tuple, set)) else [cc])
    if bcc: send_list += list(bcc if isinstance(bcc, (list, tuple, set)) else [bcc])
    try:
        if cfg["use_ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ssl.create_default_context()) as smtp:
                if cfg["user"] and cfg["password"]: smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg, from_addr=sender_addr, to_addrs=send_list)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as smtp:
                smtp.ehlo()
                if cfg["use_tls"]:
                    smtp.starttls(context=ssl.create_default_context()); smtp.ehlo()
                if cfg["user"] and cfg["password"]: smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg, from_addr=sender_addr, to_addrs=send_list)
        print(f"[mail] sent to {send_list}"); return True
    except Exception as e:
        print(f"[mail] error: {e}"); return False

# ====== 小物 ======
def _is_hashed(val: str) -> bool:
    return isinstance(val, str) and (val.startswith("pbkdf2:") or val.startswith("scrypt:"))

def _ensure_hashed(val: str) -> str:
    return val if _is_hashed(val) else generate_password_hash(val or "")

def _to_int(val, default=0):
    try:
        v = int(float(val)); return max(v, 0)
    except Exception:
        return default

def _parse_ymd(s, default=None):
    try:
        return datetime.strptime(str(s), "%Y-%m-%d").date()
    except Exception:
        return default

def next_id(items):
    return (max([x["id"] for x in items]) + 1) if items else 1

def _parse_rate(val):
    try:
        s = str(val).strip().replace('%','')
        r = float(s)
        if r > 1: r = r / 100.0
        if r < 0: r = 0.0
        if r > 1: r = 1.0
        return r
    except Exception:
        return None

def effective_commission_rate(store_id, host_id=None, liquor_id=None):
    settings = load_settings()
    base = float(settings.get("default_commission_rate", 0))
    cfg = load_commissions().get(str(store_id), {})
    r_liq = cfg.get("per_liquor", {}).get(str(liquor_id)) if liquor_id else None
    r_host = cfg.get("per_host", {}).get(str(host_id)) if host_id else None
    for r in (r_liq, r_host, base):
        try:
            if r is not None:
                return float(r)
        except Exception:
            continue
    return 0.0

def migrate_passwords():
    try:
        settings = load_settings()
        admin_pw = settings.get("admin_password", "")
        if admin_pw and not _is_hashed(admin_pw):
            settings["admin_password"] = generate_password_hash(admin_pw)
            save_settings(settings)
    except Exception:
        pass
    try:
        stores = load_stores()
        changed = False
        for s in stores:
            pw = s.get("password", "")
            if pw and not _is_hashed(pw):
                s["password"] = generate_password_hash(pw); changed = True
        if changed: save_stores(stores)
    except Exception:
        pass

migrate_passwords()

# ====== SSE ======
_SUBS = defaultdict(list)

def _sse_broadcast(store_id, kind, data):
    try:
        payload = json.dumps({"type": kind, "data": data}, ensure_ascii=False)
    except Exception:
        payload = json.dumps({"type": kind, "data": {}})
    for q in list(_SUBS[store_id]):
        try:
            q.put_nowait(payload)
        except Exception:
            pass

def _store_context():
    sid = session.get("store_id")
    stores = load_stores()
    return next((s for s in stores if s["id"] == sid), None)

@bp.route("/store/events")
@store_required
def store_events():
    store = _store_context()
    q = queue.Queue(maxsize=100)
    _SUBS[store["id"].__int__() if hasattr(store["id"], "__int__") else store["id"]].append(q)

    def gen():
        try:
            # 最初の疎通
            yield "event: ping\ndata: {\"ok\": true}\n\n"

            # CRMアラート（任意）
            try:
                alerts = _calc_crm_alerts(store)
                payload = json.dumps({"type": "crm_alerts", "data": alerts}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
            except Exception:
                pass

            # 初期席スナップショットを seat_update で送信
            try:
                for s in load_seats():
                    if s.get("store_id") != store["id"]:
                        continue
                    msg = {
                        "type": "seat_update",
                        "data": {
                            "id": int(s.get("id") or 0),
                            "label": s.get("label") or "",
                            "open": bool(s.get("open") or False),
                            "guest_name": s.get("guest_name") or "",
                            "host_id": int(s.get("host_id") or 0),
                            "customer_id": int(s.get("customer_id") or 0),
                            "items": _seat_items_simple(s.get("items"))
                        }
                    }
                    yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
            except Exception:
                pass

            # 通常のブロードキャスト
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        except GeneratorExit:
            pass
        finally:
            try:
                _SUBS[store["id"]].remove(q)
            except Exception:
                pass

    resp = Response(stream_with_context(gen()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


# ====== 管理画面（Admin） ======
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
                if v == "": continue
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
    next_id_ = (max([s["id"] for s in stores]) + 1) if stores else 1
    added = 0
    for row in reader:
        name     = (row.get("name") or "").strip()
        address  = (row.get("address") or "").strip()
        phone    = (row.get("phone") or "").strip()
        contact  = (row.get("contact") or "").strip()
        login_id = (row.get("login_id") or "").strip()
        password = (row.get("password") or "").strip()
        is_active = str(row.get("is_active", "true")).lower() not in ("0","false","no")
        if not all([name, address, phone, contact, login_id, password]): 
            continue
        if login_id in existing: 
            continue
        stores.append({
            "id": next_id_, "name": name, "address": address, "phone": phone,
            "contact": contact, "login_id": login_id, "password": _ensure_hashed(password),
            "is_active": is_active
        })
        existing.add(login_id); next_id_ += 1; added += 1
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
    save_hosts(hosts)
    return jsonify({"ok": True, "id": new_id})

@bp.route("/hosts/delete", methods=["POST"])
@admin_required
def hosts_delete():
    data = request.get_json() or {}
    ids = set(int(i) for i in (data.get("ids") or []))
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400
    hosts = [h for h in load_hosts() if h["id"] not in ids]
    save_hosts(hosts)
    return jsonify({"ok": True, "deleted": list(ids)})

@bp.route("/hosts/export")
@admin_required
def hosts_export():
    hosts = load_hosts()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id","store_id","name"])
    writer.writeheader()
    for h in hosts:
        writer.writerow({"id":h.get("id"),"store_id":h.get("store_id"),"name":h.get("name")})
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=hosts.csv"
    return resp

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
            "admin_password": _ensure_hashed(request.form.get("admin_password") or "password"),
        }
        save_settings(data)
        flash("設定を保存しました。")
        return redirect(url_for("admin.settings"))
    s = load_settings()
    return render_template("settings.html", s=s)

@bp.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        # どんなキー名でも拾う（password / admin_password / pass / pwd）
        data = request.get_json(silent=True) or {}
        pwd = (
            request.form.get("password")
            or request.form.get("admin_password")
            or request.form.get("pass")
            or request.form.get("pwd")
            or data.get("password")
            or data.get("admin_password")
            or data.get("pass")
            or data.get("pwd")
            or ""
        ).strip()

        st = _load_settings()
        hpw = st.get("admin_password", "")

        ok = False
        if hpw:
            try:
                ok = check_password_hash(hpw, pwd)
            except Exception as e:
                current_app.logger.exception("[LOGIN] check_password_hash failed: %s", e)
                err = "内部エラー"
        else:
            err = "管理パスワードが未設定です（settings.json）"

        if ok:
            session["admin_logged_in"] = True
            return redirect(url_for("admin.dashboard"))
        if not err:
            err = "パスワードが違います"

    return render_template("admin_login.html", error=err)

@bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin.login"))

# ====== 店舗アカウント ======
@bp.route("/store/login", methods=["GET", "POST"])
def store_login():
    message = None
    if request.method == "POST":
        login_id = (request.form.get("login_id") or "").strip()
        password = (request.form.get("password") or "").strip()
        remember = bool(request.form.get("remember"))
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
                        s["password"] = generate_password_hash(password)
                        save_stores(stores)
                        store = s
                if store: break
        if store:
            if not store.get("is_active", True):
                message = "この店舗は一時停止中のためログインできません。"
            else:
                session["store_id"] = store["id"]
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

@bp.route("/store/logout")
def store_logout():
    session.pop("store_id", None)
    return redirect(url_for("admin.store_login"))

@bp.route("/store")
@store_required
def store_home():
    return redirect(url_for("admin.store_ops"))

@bp.route("/store/dashboard")
@store_required
def store_dashboard():
    store = getattr(g, "current_store", None)
    if not store:
        return redirect(url_for("admin.store_login"))
    hosts = load_hosts()
    host_count = sum(1 for h in hosts if h.get("store_id") == store["id"])
    return render_template("store_dashboard.html", store=store, host_count=host_count)

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
    busy_ids = {
        s.get("host_id")
        for s in load_seats()
        if s.get("store_id") == store["id"] and s.get("open")
    }
    def sort_key(h):
        return (
            0 if h.get("on_duty") else 1,
            0 if h.get("id") in busy_ids else 1,
            (h.get("name") or "").lower(),
        )
    hosts_sorted = sorted(hosts, key=sort_key)
    return render_template("store_hosts.html", active="hosts", store=store, hosts=hosts_sorted, busy_ids=busy_ids)

@bp.route("/store/hosts/create", methods=["POST"])
@store_required
def store_hosts_create():
    store = _store_context()
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name_required"}), 400
    hosts = load_hosts()
    new_id_ = next_id(hosts)
    hosts.append({
        "id": new_id_,
        "store_id": store["id"],
        "name": name,
        "on_duty": bool(data.get("on_duty"))
    })
    save_hosts(hosts)
    return jsonify({"ok": True, "id": new_id_})

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
    hosts = load_hosts()
    keep = [h for h in hosts if not (h.get("store_id")==store["id"] and h.get("id") in ids)]
    save_hosts(keep)
    seats = load_seats()
    changed = False
    for s in seats:
        if s.get("store_id")==store["id"] and s.get("host_id") in ids:
            s["host_id"] = 0
            changed = True
    if changed:
        save_seats(seats)
    return jsonify({"ok": True, "deleted": list(ids)})

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
    save_hosts(hosts)
    return jsonify({"ok": True, "id": host_id, "on_duty": on})

@bp.route("/store/hosts/<int:host_id>")
@store_required
def store_host_detail(host_id):
    store = _store_context()
    host = next((h for h in load_hosts() if h.get("id")==host_id and h.get("store_id")==store["id"]), None)
    if not host:
        return redirect(url_for('admin.store_hosts'))
    import datetime as dt
    today = dt.datetime.now().strftime("%Y-%m-%d")
    this_month = dt.datetime.now().strftime("%Y-%m")
    sales = [s for s in load_sales() if s.get("store_id")==store["id"] and s.get("host_id")==host_id]
    total_today = sum(s.get("total",0) for s in sales if s.get("date")==today)
    total_month = sum(s.get("total",0) for s in sales if s.get("month")==this_month)
    comm_today = sum(s.get("commission_total",0) for s in sales if s.get("date")==today)
    comm_month = sum(s.get("commission_total",0) for s in sales if s.get("month")==this_month)
    comm_cfg = load_commissions().get(str(store["id"]), {"per_host":{}, "per_liquor":{}})
    host_rate = comm_cfg.get("per_host", {}).get(str(host_id))
    return render_template("store_host_detail.html",
                           active="hosts", store=store, host=host,
                           sales=sales, total_today=total_today, total_month=total_month,
                           comm_today=comm_today, comm_month=comm_month, host_rate=host_rate)

# ====== OPS / 注文・会計 ======
@bp.route("/store/ops")
@store_required
def store_ops():
    store = _store_context()
    liquors = [x for x in load_liquors() if x.get("store_id") == store["id"]]
    seats = [x for x in load_seats() if x.get("store_id") == store["id"]]
    hosts = [h for h in load_hosts() if h.get("store_id") == store["id"]]
    return render_template("store_ops.html", active="ops",
                           store=store, liquors=liquors, seats=seats, hosts=hosts)

def _maybe_notify_low_stock(store, liquor, liquors_all):
    stock = int(liquor.get("stock") or 0)
    rp    = int(liquor.get("reorder_point") or 0)
    if rp <= 0: return False
    if stock > rp and liquor.get("low_notified"):
        liquor.pop("low_notified", None)
        liquors_all and save_liquors(liquors_all)
        return False
    if stock == rp and not liquor.get("low_notified"):
        to = (liquor.get("vendor_email") or "").strip()
        if not to:
            print("[stock-mail] skip: no vendor_email"); return False
        to_name = (liquor.get("vendor_name") or "").strip()
        today = datetime.now().strftime("%Y-%m-%d")
        atena = f"{to_name} 様" if to_name else f"{store.get('name','店舗')} 様"
        subj = f"[発注メール] {store.get('name','')} - {liquor.get('name','不明')} 在庫下限"
        body = (
            f"{atena}\n\n"
            f"以下の酒類が在庫下限に到達しました。\n"
            f"  商品名 : {liquor.get('name','')}\n"
            f"  在庫   : {stock}\n"
            f"  下限   : {rp}\n"
            f"  店舗名 : {store.get('name','店舗')}\n\n"
            f"発注よろしくお願い致します。\n"
            f"（自動通知: 内職君 / {today}）\n"
        )
        ok = _send_email(
            to, subj, body,
            from_name=store.get("name"),
            from_addr=store.get("from_email") or None
        )
        if ok:
            liquor["low_notified"] = True
            liquors_all and save_liquors(liquors_all)
        return ok
    return False

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
    if cur_stock < 1 or cur_stock < qty:
        return jsonify({"ok":False,"error":"no_stock"}), 400

    liquor["stock"] = cur_stock - qty
    save_liquors(liquors)
    _sse_broadcast(store["id"], "inventory_update", {
      "id": liquor["id"], "name": liquor.get("name"),
      "sale_price": int(liquor.get("sale_price") or 0),
      "stock": int(liquor.get("stock") or 0)
    })

    unit_price = int(liquor.get("sale_price") or 0)
    seat.setdefault("items", []).append({
        "liquor_id": lid,
        "name": liquor.get("name"),
        "qty": qty,
        "unit_price": unit_price
    })
    save_seats(seats)

    _sse_broadcast(store["id"], "order_added", {
        "seat_id": seat["id"],
        "item": {"name": liquor.get("name"), "qty": qty, "unit_price": unit_price}
    })
    _sse_broadcast(store["id"], "seat_update", {
        "id": seat["id"],
        "open": seat.get("open", True),
        "guest_name": seat.get("guest_name") or "",
        "host_id": seat.get("host_id") or 0,
        "customer_id": int(seat.get("customer_id") or 0),
        "items": _seat_items_simple(seat.get("items"))
    })

    try:
        _maybe_notify_low_stock(store, liquor, liquors)
    except Exception as e:
        print(f"[stock-mail] notify error (ignored): {e}")

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

    def _i(v):
        try: return int(float(v))
        except Exception: return 0

    items = seat.get("items") or []
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
        commission_details.append({"liquor_id": lid, "rate": rate, "amount": amount})

    nowdate = datetime.now()
    sale = {
        "id": next_id(load_sales()),
        "store_id": store["id"],
        "seat_label": seat.get("label"),
        "host_id": host_id_for_comm,
        "guest_name": seat.get("guest_name") or "",
        "customer_id": int(seat.get("customer_id") or 0),
        "items": safe_items,
        "total": total,
        "commission_total": commission_total,
        "commission_details": commission_details,
        "date": nowdate.strftime("%Y-%m-%d"),
        "month": nowdate.strftime("%Y-%m")
    }
    sales = load_sales()
    sales.append(sale)
    save_sales(sales)

    # 顧客へ最終来店反映
    cid = int(seat.get("customer_id") or 0)
    if cid:
        customers = load_customers()
        c = next((x for x in customers if x.get("id")==cid and x.get("store_id")==store["id"]), None)
        if c:
            c["last_visit_at"] = nowdate.strftime("%Y-%m-%dT%H:%M:%S")
            c["recent_items"]  = [{"name": it["name"], "qty": int(it["qty"])} for it in safe_items]
            save_customers(customers)

    # 席リセット
    seat.update({"open": False, "guest_name": "", "host_id": 0, "customer_id": 0, "items": []})
    save_seats(seats)

    inv_url = url_for("admin.store_invoice", sale_id=sale["id"])

    # 会計完了通知
    _sse_broadcast(store["id"], "checkout_done", {
      "seat_id": seat["id"], "sale_id": sale["id"], "invoice_url": inv_url
    })
    # 空席の seat_update も投げてフロント再描画を確実に
    _sse_broadcast(store["id"], "seat_update", {
        "id": seat["id"],
        "label": seat.get("label") or "",
        "open": False,
        "guest_name": "",
        "host_id": 0,
        "customer_id": 0,
        "items": []
    })
    return jsonify({"ok": True, "total": total, "sale_id": sale["id"], "invoice_url": inv_url})

# ====== 分析/在庫/手数料 ======
@bp.route("/store/analytics")
@store_required
def store_analytics():
    store = _store_context()
    sales = [s for s in load_sales() if s.get("store_id")==store["id"]]
    host_map = {h["id"]: h["name"] for h in load_hosts() if h.get("store_id")==store["id"]}
    return render_template("store_analytics.html", active="analytics",
                           store=store, sales=sales, host_map=host_map)

@bp.route("/store/analytics/data")
@store_required
def store_analytics_data():
    store = _store_context()
    today = datetime.now().date()
    first = today.replace(day=1)
    q_from = _parse_ymd(request.args.get("from"), first)
    q_to   = _parse_ymd(request.args.get("to"),   today)
    if q_from is None: q_from = first
    if q_to is None:   q_to   = today
    group = (request.args.get("group") or "daily").lower()
    all_sales = [s for s in load_sales() if s.get("store_id") == store["id"]]
    sales = []
    for s in all_sales:
        d = _parse_ymd(s.get("date"))
        if d is None:
            try:
                d = datetime.strptime(s.get("month"), "%Y-%m").date().replace(day=1)
            except Exception:
                continue
        if q_from <= d <= q_to:
            sales.append(s)
    labels, totals, table = [], [], []
    host_map = {h["id"]: h["name"] for h in load_hosts() if h.get("store_id")==store["id"]}
    if group == "daily":
        acc, cnt = {}, {}
        for s in sales:
            k = s.get("date")
            acc[k] = acc.get(k, 0) + int(s.get("total", 0))
            cnt[k] = cnt.get(k, 0) + 1
        for k in sorted(acc.keys()):
            labels.append(k); totals.append(acc[k]); table.append({"label": k, "total": acc[k], "count": cnt.get(k,0)})
    elif group == "host":
        acc, cnt = {}, {}
        for s in sales:
            hid = int(s.get("host_id") or 0)
            acc[hid] = acc.get(hid, 0) + int(s.get("total", 0))
            cnt[hid] = cnt.get(hid, 0) + 1
        for hid, val in sorted(acc.items(), key=lambda x: x[1], reverse=True):
            name = host_map.get(hid, f"ID:{hid or '-'}")
            labels.append(name); totals.append(val)
            table.append({"label": name, "total": val, "count": cnt.get(hid,0), "host_id": hid})
    else:
        acc, cnt = {}, {}
        for s in sales:
            for it in (s.get("items") or []):
                lid = int(it.get("liquor_id") or 0)
                name = it.get("name") or f"ID:{lid or '-'}"
                amt = int(it.get("qty",0)) * int(it.get("unit_price",0))
                acc[name] = acc.get(name, 0) + amt
                cnt[name] = cnt.get(name, 0) + int(it.get("qty",0))
        for name, val in sorted(acc.items(), key=lambda x: x[1], reverse=True):
            labels.append(name); totals.append(val)
            table.append({"label": name, "total": val, "count": cnt.get(name,0)})
    return jsonify({
        "ok": True,
        "from": q_from.strftime("%Y-%m-%d"),
        "to":   q_to.strftime("%Y-%m-%d"),
        "group": group,
        "labels": labels,
        "totals": totals,
        "table": table
    })

@bp.route("/store/liquors/status")
@store_required
def store_liquors_status():
    store = _store_context()
    items = [
        {
            "id": x["id"],
            "name": x.get("name",""),
            "sale_price": int(x.get("sale_price") or 0),
            "stock": int(x.get("stock") or 0),
        }
        for x in load_liquors() if x.get("store_id")==store["id"]
    ]
    return jsonify({"ok": True, "items": items})

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
    return render_template("store_inventory.html", active="inventory", store=store, liquors=liquors)

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

@bp.route("/store/liquors/create", methods=["POST"])
@store_required
def store_liquors_create():
    store = _store_context()
    data = request.get_json(silent=True) or request.form.to_dict() or {}
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

    # ★ 重複判定（店舗内 同名を正規化して比較）
    def _key(s): 
        return _norm_text(s).replace(" ", "").lower()
    key_new = _key(name)
    existing = next((x for x in items 
                     if x.get("store_id")==store["id"] and _key(x.get("name",""))==key_new), None)

    if existing:
        # 既存を更新（新規作成しない）
        existing.update({
            "name": name,
            "sale_price": sale,
            "cost_price": cost,
            "reorder_point": reorder,
            "stock": stock if stock else int(existing.get("stock") or 0),
            "vendor_email": vendor,
            "vendor_name": vendor_name
        })
        save_liquors(items)
        _sse_broadcast(store["id"], "inventory_update", {
            "id": existing["id"],
            "name": existing.get("name"),
            "sale_price": int(existing.get("sale_price") or 0),
            "stock": int(existing.get("stock") or 0)
        })
        return jsonify({"ok": True, "id": existing["id"], "updated": True})

    # ここから新規作成
    new_id_ = next_id(items)
    items.append({
        "id": new_id_, "store_id": store["id"], "name": name,
        "sale_price": sale, "cost_price": cost, "reorder_point": reorder, "stock": stock,
        "vendor_email": vendor, "vendor_name": vendor_name
    })
    save_liquors(items)
    _sse_broadcast(store["id"], "inventory_update", {
      "id": new_id_, "name": name, "sale_price": sale, "stock": stock
    })
    return jsonify({"ok": True, "id": new_id_})

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
    if not target: 
        return jsonify({"ok":False,"error":"not_found"}), 404
    for k in ("name","sale_price","cost_price","reorder_point","stock","vendor_email","vendor_name"):
        if k in data and data[k] is not None:
            v = data[k]
            if k in ("sale_price","cost_price","reorder_point","stock"):
                v = _to_int(v)
            else:
                v = (str(v) if v is not None else "").strip()
            target[k] = v
    save_liquors(items)
    _maybe_notify_low_stock(store, target, items)
    _sse_broadcast(store["id"], "inventory_update", {
      "id": target["id"],
      "name": target.get("name"),
      "sale_price": int(target.get("sale_price") or 0),
      "stock": int(target.get("stock") or 0)
    })
    return jsonify({"ok": True})

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
            deleted.append(int(x.get("id"))); continue
        keep.append(x)
    save_liquors(keep)
    for _id in deleted:
        _sse_broadcast(store["id"], "liquor_deleted", {"id": _id})
    return jsonify({"ok": True, "deleted": deleted})

# ====== テキスト整形/検索ヘルパ ======
def _norm_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = s.replace("\u3000", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _to_ascii_digits(s: str) -> str:
    return s.translate(str.maketrans("０１２３４５６７８９", "0123456789"))

def _find_seat_by_label(store_id: int, label: str):
    if not label: return None
    want = str(label).lower()
    for s in load_seats():
        if s.get("store_id") == store_id and str(s.get("label") or "").lower() == want:
            return s
    return None

def _find_liquor_by_text(store_id: int, text: str):
    q = _to_ascii_digits(_norm_text(text)).replace(" ", "").lower()
    if not q: return None
    cands = [l for l in load_liquors() if l.get("store_id") == store_id]
    cands.sort(key=lambda l: len(str(l.get("name") or "")), reverse=True)
    for l in cands:
        name = _norm_text(l.get("name") or "").replace(" ", "").lower()
        if name and name in q:
            return l
    return None

def _seat_items_simple(items):
    out = []
    for it in (items or []):
        try:
            q  = int(it.get("qty") or 0)
            up = int(it.get("unit_price") or 0)
        except Exception:
            q, up = 0, 0
        out.append({"name": it.get("name"), "qty": q, "unit_price": up})
    return out

# ====== CRMアラート/誕生日補助 ======
def _calc_crm_alerts(store):
    today = datetime.now().date()
    dormant_days = int((load_settings().get("dormant_days_by_store", {}) or {}).get(str(store["id"]), 30))

    def _is_target_bday(bday_str):
        if not bday_str: return None
        try:
            if len(bday_str) == 5:  # MM-DD
                b = datetime.strptime(f"{today.year}-{bday_str}", "%Y-%m-%d").date()
            else:
                b = datetime.strptime(bday_str, "%Y-%m-%d").date()
            b_this = b.replace(year=today.year)
        except Exception:
            return None
        delta = (b_this - today).days
        if delta < -200:
            b_this = b_this.replace(year=today.year + 1)
            delta = (b_this - today).days
        if delta in (7, 1):
            return delta
        return None

    customers = [c for c in load_customers() if c.get("store_id")==store["id"]]
    birthdays = []
    for c in customers:
        d = _is_target_bday(c.get("birthday"))
        if d is not None:
            birthdays.append({"id": c["id"], "name": c.get("name"), "days_before": d})

    dormant = []
    for c in customers:
        lv = c.get("last_visit_at")
        if not lv: continue
        try:
            last = datetime.strptime(lv, "%Y-%m-%dT%H:%M:%S").date()
        except Exception:
            continue
        days = (today - last).days
        if days >= dormant_days:
            dormant.append({"id": c["id"], "name": c.get("name"), "days": days})

    return {"birthdays": birthdays, "dormant": dormant}

def _days_until_bday(s):
    if not s: return None
    try:
        today = datetime.now().date()
        if len(s) == 5:  # MM-DD
            m, d = [int(x) for x in s.split("-")]
            this = today.replace(month=m, day=d)
        else:
            _, m, d = [int(x) for x in s.split("-")]
            this = today.replace(month=m, day=d)
        if this < today:
            this = this.replace(year=today.year + 1)
        return (this - today).days
    except Exception:
        return None

# ====== 顧客管理 ======
@bp.route("/store/customers")
@store_required
def store_customers():
    store = _store_context()
    customers = [c for c in load_customers() if c.get("store_id")==store["id"]]
    hosts = [h for h in load_hosts() if h.get("store_id")==store["id"]]

    # 設定（無ければ既定値）
    s = load_settings() or {}
    dormant_days = int((s.get("dormant_days_by_store",{}) or {}).get(str(store["id"]), 30))
    bdays_window = int((s.get("birthday_window_days_by_store",{}) or {}).get(str(store["id"]), 7))

    # 誕生日(今後 bdays_window 日以内)
    upcoming_birthdays = []
    for c in customers:
        left = _days_until_bday(c.get("birthday",""))
        if left is not None and 0 <= left <= bdays_window:
            upcoming_birthdays.append({
                "id": c["id"],
                "name": c.get("name",""),
                "days_left": left,
                "birthday": c.get("birthday",""),
                "default_host_id": int(c.get("default_host_id") or 0)
            })
    upcoming_birthdays.sort(key=lambda x: (x["days_left"], x["name"]))

    # 休眠（last_visit_at から dormant_days 経過）
    dormant_list = []
    today = datetime.now().date()
    for c in customers:
        lv = c.get("last_visit_at")
        if not lv:
            # 未来店扱い
            dormant_list.append({"id": c["id"], "name": c.get("name",""), "days": "（未来店）"})
            continue
        try:
            last = datetime.strptime(lv, "%Y-%m-%dT%H:%M:%S").date()
        except Exception:
            continue
        days = (today - last).days
        if days >= dormant_days:
            dormant_list.append({"id": c["id"], "name": c.get("name",""), "days": days})
    # 日数降順・未来店最後
    dormant_list.sort(key=lambda x: (isinstance(x["days"], int), x["days"] if isinstance(x["days"], int) else -1), reverse=True)

    # 一覧用サマリ
    rows = []
    host_map = {h["id"]: h["name"] for h in hosts}
    for c in customers:
        last_visit_date = ""
        if c.get("last_visit_at"):
            try:
                last_visit_date = datetime.strptime(c["last_visit_at"], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d")
            except Exception:
                last_visit_date = ""
        rows.append({
            "id": c["id"],
            "name": c.get("name",""),
            "default_host": host_map.get(int(c.get("default_host_id") or 0), "-"),
            "last_visit": last_visit_date,
            "visit_count": int(c.get("visit_count") or 0),
            "keep": c.get("keep_liquor_name",""),
            "birthday": c.get("birthday",""),
        })

    return render_template(
        "store_customers.html",
        active="customers",
        store=store,
        hosts=hosts,
        rows=rows,
        upcoming_birthdays=upcoming_birthdays,
        dormant_list=dormant_list,
        dormant_days=dormant_days,
        bdays_window=bdays_window
    )


# ... 既存の import や関数の上はそのまま ...

@bp.route("/store/customers/<int:cid>")
@store_required
def store_customer_detail(cid):
    store = _store_context()

    # 同店舗のホストだけに絞る
    hosts = [h for h in load_hosts() if int(h.get("store_id") or 0) == int(store["id"])]

    customers = load_customers() or []
    c = next(
        (x for x in customers
         if int(x.get("id") or 0) == int(cid) and int(x.get("store_id") or 0) == int(store["id"])),
        None
    )
    if not c:
        abort(404)

    # 来店履歴
    visits = [v for v in load_visits()
              if int(v.get("store_id") or 0) == int(store["id"])
              and int(v.get("customer_id") or 0) == int(cid)]

    # --- 保存済み NG（ID と 名前）を準備 ---
    # ng_ids_saved: テンプレ側 multiple セレクトの selected 判定用
    ng_ids_saved = []
    raw = c.get("ng_host_ids") or []
    if isinstance(raw, list):
        for v in raw:
            try:
                ng_ids_saved.append(int(v))
            except Exception:
                pass
    # 互換: 単数の ng_host_id が残っていたら混ぜておく
    try:
        one = int(c.get("ng_host_id") or 0)
        if one and one not in ng_ids_saved:
            ng_ids_saved.append(one)
    except Exception:
        pass
    ng_ids_saved = sorted(set(ng_ids_saved))

    # ng_names: 「現在のNGホスト（保存済み）」表示用の名前リスト
    ng_names = _resolve_ng_names_for_customer(c, hosts, store["id"])

    # デバッグログ（必要なければ削除可）
    print("[NGDEBUG]",
          "raw_ids=", c.get("ng_host_ids"),
          "single=", c.get("ng_host_id"),
          "resolved=", ng_names)

    return render_template(
        "store_customer_detail.html",
        active="customers",
        store=store,
        c=c,
        hosts=hosts,
        visits=visits,
        ng_ids_saved=ng_ids_saved,  # セレクトの selected 用
        ng_names=ng_names,          # 「現在のNGホスト（保存済み）」表示用
    )


# ====== 店舗のメールFrom/休眠・誕生日設定 ======
@bp.route("/store/settings", methods=["GET","POST"])
@store_required
def store_settings_page():
    store = _store_context()
    s = load_settings() or {}
    if request.method == "POST":
        from_email   = (request.form.get("from_email") or "").strip()
        dormant_days = int(request.form.get("dormant_days") or 30)
        bdays_window = int(request.form.get("birthday_window_days") or 7)

        # 店舗の from_email
        stores = load_stores()
        for ss in stores:
            if ss["id"] == store["id"]:
                ss["from_email"] = from_email
                save_stores(stores)
                break

        # 店舗別設定
        dd = s.get("dormant_days_by_store", {}) or {}
        dd[str(store["id"])] = dormant_days
        s["dormant_days_by_store"] = dd

        bw = s.get("birthday_window_days_by_store", {}) or {}
        bw[str(store["id"])] = bdays_window
        s["birthday_window_days_by_store"] = bw

        save_settings(s)
        store = _store_context()
        return render_template("store_settings.html",
            active="settings", store=store, s=s, saved=True)

    return render_template("store_settings.html", active="settings", store=store, s=s)

# admin/routes.py に追加（または既存の同名関数を置き換え）
@bp.route("/store/seats/delete", methods=["POST"])
@store_required
def store_seats_delete():  # endpoint: admin.store_seats_delete
    store = _store_context()
    data = request.get_json(silent=True) or {}

    # ids / id の両対応
    raw_ids = data.get("ids")
    if raw_ids is None and "id" in data:
        raw_ids = [data.get("id")]
    ids = {int(i) for i in (raw_ids or []) if str(i).isdigit()}
    if not ids:
        return jsonify({"ok": False, "error": "no_ids"}), 400

    seats = load_seats()
    keep = []
    deleted = []
    for s in seats:
        if s.get("store_id") == store["id"] and int(s.get("id") or 0) in ids:
            deleted.append(int(s.get("id") or 0))
            continue
        keep.append(s)
    save_seats(keep)

    # SSE 通知（フロント再描画用）
    for sid in deleted:
        _sse_broadcast(store["id"], "seat_deleted", {"id": sid})

    return jsonify({"ok": True, "deleted": deleted})

# --- seats list (テンプレからの初期表示用) ---
@bp.get("/store/seats/list")
@store_required
def store_seats_list():  # endpoint: admin.store_seats_list
    store = _store_context()
    # この店舗の席だけ返す
    seats = [
        {
            "id": int(s.get("id") or 0),
            "label": s.get("label") or "",
            "open": bool(s.get("open") or False),
            "host_id": int(s.get("host_id") or 0),
            "guest_name": s.get("guest_name") or "",
            "customer_id": int(s.get("customer_id") or 0),
            "items": _seat_items_simple(s.get("items"))
        }
        for s in load_seats()
        if s.get("store_id") == store["id"]
    ]
    return jsonify({"ok": True, "seats": seats})

# --- admin/routes.py に追記 ---
from flask import request, jsonify
from datetime import datetime

# 先頭付近に無ければ
from flask import request, jsonify

# 顧客 保存
@bp.route("/store/customers/save", methods=["POST"])
@store_required
def store_customers_save():
    store = _store_context()
    data = request.get_json(silent=True) or {}
    cid  = int(data.get("id") or 0)

    customers = load_customers()
    target = None
    for c in customers:
        if int(c.get("id") or 0) == cid and int(c.get("store_id") or 0) == int(store["id"]):
            target = c
            break
    if not target:
        return jsonify({"ok": False, "error": "not_found"}), 404

    # 基本項目
    target["name"]              = str(data.get("name") or "").strip()
    target["default_host_id"]   = int(data.get("default_host_id") or 0)
    target["birthday"]          = str(data.get("birthday") or "").strip()     # "YYYY-MM-DD" or "MM-DD"
    target["keep_liquor_name"]  = str(data.get("keep_liquor_name") or "").strip()
    target["memo"]              = str(data.get("memo") or "")

    # NGホスト（複数）
    raw_ng = data.get("ng_host_ids") or []
    ng_ids = []
    for v in raw_ng:
        try:
            iv = int(v)
            if iv > 0:
                ng_ids.append(iv)
        except Exception:
            pass
    target["ng_host_ids"] = sorted(set(ng_ids))

    # 表示用：担当ホスト名を同期
    host_name = ""
    for h in load_hosts():
        if int(h.get("store_id") or 0) == int(store["id"]) and int(h.get("id") or 0) == int(target["default_host_id"] or 0):
            host_name = str(h.get("name") or "")
            break
    target["default_host_name"] = host_name

    save_customers(customers)
    return jsonify({"ok": True})


# 顧客 削除
@bp.route("/store/customers/delete", methods=["POST"])
@store_required
def store_customers_delete():
    store = _store_context()
    data  = request.get_json(silent=True) or {}
    cid   = int(data.get("id") or 0)

    customers = load_customers()
    new_customers = [c for c in customers
                     if not (int(c.get("id") or 0) == cid and int(c.get("store_id") or 0) == int(store["id"]))]

    if len(new_customers) == len(customers):
        return jsonify({"ok": False, "error": "not_found"}), 404

    save_customers(new_customers)

    # 座席の紐付きを外す（残っているとエラー/表示不整合の元）
    seats = load_seats()
    changed = False
    for s in seats:
        if int(s.get("store_id") or 0) == int(store["id"]) and int(s.get("customer_id") or 0) == cid:
            s["customer_id"] = 0
            changed = True
    if changed:
        save_seats(seats)

    return jsonify({"ok": True})
