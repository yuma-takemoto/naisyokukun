import os
import json
import re
import unicodedata
from collections import deque
from datetime import datetime
from flask import request
from . import bp  # Blueprint

from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage

# ==== 設定/ファイル ==== #
BASE_DIR      = os.path.dirname(os.path.dirname(__file__))  # プロジェクト直下
INSTANCE_DIR  = os.path.join(BASE_DIR, "instance")
SETTINGS_JSON = os.path.join(INSTANCE_DIR, "settings.json")
HOSTS_JSON    = os.path.join(INSTANCE_DIR, "hosts.json")
LINKS_JSON    = os.path.join(INSTANCE_DIR, "line_links.json")  # LINEユーザーとホストの紐付け
SEATS_JSON    = os.path.join(INSTANCE_DIR, "seats.json")
LIQUORS_JSON  = os.path.join(INSTANCE_DIR, "liquors.json")
SALES_JSON    = os.path.join(INSTANCE_DIR, "sales.json")

# 顧客/来店
CUSTOMERS_JSON = os.path.join(INSTANCE_DIR, "customers.json")
VISITS_JSON    = os.path.join(INSTANCE_DIR, "visits.json")

def _load_json(path, default):
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default, f, ensure_ascii=False, indent=2)
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _load_settings():   return _load_json(SETTINGS_JSON, {})

def _load_hosts():      return _load_json(HOSTS_JSON, [])
def _save_hosts(d):     _save_json(HOSTS_JSON, d)

def _load_links():      return _load_json(LINKS_JSON, {})
def _save_links(d):     _save_json(LINKS_JSON, d)

def _load_seats():      return _load_json(SEATS_JSON, [])
def _save_seats(d):     _save_json(SEATS_JSON, d)

def _load_liquors():    return _load_json(LIQUORS_JSON, [])
def _save_liquors(d):   _save_json(LIQUORS_JSON, d)

def _load_sales():      return _load_json(SALES_JSON, [])

# ★ 堅牢版：customers は常に list[dict] で返す
def _load_customers():
    data = _load_json(CUSTOMERS_JSON, [])
    if isinstance(data, dict):
        data = list(data.values())
    out = []
    if isinstance(data, list):
        for c in data:
            if not isinstance(c, dict):
                continue
            try:
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
                    # NG互換フィールド
                    "ng_host_ids": c.get("ng_host_ids") or c.get("ng_hosts") or [],
                    "ng_host_id": int(c.get("ng_host_id") or 0),
                    "ng_host_names": c.get("ng_host_names") or [],
                })
            except Exception:
                continue
    return out

def _save_customers(d): _save_json(CUSTOMERS_JSON, d)

def _load_visits():     return _load_json(VISITS_JSON, [])
def _save_visits(d):    _save_json(VISITS_JSON, d)

_cfg = _load_settings()
CHANNEL_SECRET = _cfg.get("line_channel_secret") or os.getenv("LINE_CHANNEL_SECRET") or ""
CHANNEL_ACCESS_TOKEN = _cfg.get("line_channel_access_token") or os.getenv("LINE_CHANNEL_ACCESS_TOKEN") or ""

line_bot_api = LineBotApi(CHANNEL_ACCESS_TOKEN) if CHANNEL_ACCESS_TOKEN else None
handler = WebhookHandler(CHANNEL_SECRET or "dummy")

# ==== 二重返信ガード ==== #
_recent_tokens = deque(maxlen=256)
_recent_set = set()
def _already_replied(token: str) -> bool:
    if not token:
        return False
    if token in _recent_set:
        return True
    _recent_tokens.append(token)
    _recent_set.add(token)
    while len(_recent_set) > len(_recent_tokens):
        old = _recent_tokens.popleft()
        _recent_set.discard(old)
    return False

def _safe_reply(reply_token: str, text: str):
    if _already_replied(reply_token):
        return
    if not line_bot_api:
        print("[linebot] token missing: cannot reply")
        return
    try:
        line_bot_api.reply_message(reply_token, TextSendMessage(text=text))
    except Exception as e:
        print("[linebot] reply error:", e)

# ==== SSE発火ユーティリティ ==== #
def _emit(store_id: int, kind: str, data: dict):
    push = None
    try:
        from admin.routes import _sse_broadcast as push
    except Exception:
        try:
            from ..admin.routes import _sse_broadcast as push
        except Exception:
            push = None
    if push:
        try:
            push(store_id, kind, data)
        except Exception as e:
            print("[linebot] sse emit error:", e)

# ==== 正規化 & 検索ヘルパ ==== #
def _norm_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = s.replace("\u3000", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _to_ascii_digits(s: str) -> str:
    return s.translate(str.maketrans("０１２３４５６７８９", "0123456789"))

def _nz(v, d=""):
    return v if v is not None else d

def _find_seat_by_label(store_id: int, label: str):
    if not label:
        return None
    want = str(label).lower()
    for s in _load_seats():
        if s.get("store_id") == store_id and str(s.get("label") or "").lower() == want:
            return s
    return None

def _find_seat_in_text(store_id: int, text_raw: str):
    seats = [s for s in _load_seats() if s.get("store_id")==store_id]
    if not seats:
        return None, None
    t = _to_ascii_digits(_norm_text(text_raw)).replace(" ", "").lower()
    cand = []
    for s in seats:
        lab = (str(s.get("label") or "")).replace(" ", "").lower()
        if lab and lab in t:
            cand.append((len(lab), s, lab))
    if not cand:
        return None, None
    cand.sort(reverse=True, key=lambda x: x[0])
    _, seat, lab = cand[0]
    rest = t.replace(lab, "", 1)
    return seat, rest

def _find_liquor_by_text(store_id: int, text_raw_no_space: str):
    q = _to_ascii_digits(_norm_text(text_raw_no_space)).replace(" ", "").lower()
    if not q:
        return None, q
    cands = [l for l in _load_liquors() if l.get("store_id")==store_id]
    cands.sort(key=lambda l: len(str(l.get("name") or "")), reverse=True)
    for l in cands:
        nm = _to_ascii_digits(_norm_text(l.get("name") or "")).replace(" ", "").lower()
        if nm and nm in q:
            return l, q.replace(nm, "", 1)
    return None, q

def _parse_qty(text_no_space: str, default=1) -> int:
    m = re.search(r"(\d+)$", text_no_space or "")
    if not m:
        m = re.search(r"(\d+)", text_no_space or "")
    try:
        return max(1, int(m.group(1))) if m else default
    except Exception:
        return default

def _next_id(items):
    return (max([x.get("id", 0) for x in items]) + 1) if items else 1

def _name_key(s: str) -> str:
    return _to_ascii_digits(_norm_text(s)).replace(" ", "").lower()

def _find_customer_by_name(store_id: int, name: str):
    if not name:
        return None
    key = _name_key(name)
    for c in _load_customers():
        if int(c.get("store_id") or 0) == int(store_id) and _name_key(c.get("name") or "") == key:
            return c
    return None

def _get_host(store_id: int, host_id: int):
    for h in _load_hosts():
        if int(h.get("store_id") or 0)==int(store_id) and int(h.get("id") or 0)==int(host_id or 0):
            return h
    return None

def _upsert_customer(store_id: int, name: str, default_host_id: int):
    customers = _load_customers()
    exist = _find_customer_by_name(store_id, name)
    if exist:
        return exist, False
    host = _get_host(store_id, default_host_id)
    cid = _next_id(customers)
    c = {
        "id": cid,
        "store_id": store_id,
        "name": name,
        "default_host_id": default_host_id or 0,
        "default_host_name": (host and host.get("name")) or "",
        "birthday": "",  # "YYYY-MM-DD" または "MM-DD"
        "is_ng": False,
        "tags": [],
        "memo": "",
        "keep_liquor_id": 0,
        "keep_liquor_name": "",
        "keep_updated_at": "",
        "last_visit": "",
        "visit_count": 0,
        "total_amount": 0,
        "ng_host_ids": [],
        "ng_host_id": 0,
        "ng_host_names": [],
    }
    customers.append(c)
    _save_customers(customers)
    return c, True

def _touch_visit(store_id: int, customer: dict, seat_label: str, host_id: int, action: str):
    """action: 'start' | 'order' | 'keep'"""
    visits = _load_visits()
    visits.append({
        "id": _next_id(visits),
        "store_id": store_id,
        "customer_id": customer and customer.get("id") or 0,
        "customer_name": customer and customer.get("name") or "",
        "seat_label": seat_label,
        "host_id": host_id,
        "action": action,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    _save_visits(visits)
    # 顧客の最終来店・回数
    if customer:
        customers = _load_customers()
        for c in customers:
            if c.get("id")==customer.get("id"):
                c["last_visit"] = datetime.now().strftime("%Y-%m-%d")
                c["visit_count"] = int(c.get("visit_count") or 0) + (1 if action=="start" else 0)
                break
        _save_customers(customers)

# ===== 管理側互換: seat items をSSEで返すための整形 =====
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

# ===== NGホスト名の解決（PC側の保存形式に頑健に対応） =====
def _resolve_ng_host_names(customer: dict, store_id: int):
    names = set()
    for nm in (customer.get("ng_host_names") or []):
        try:
            s = str(nm).strip()
            if s:
                names.add(s)
        except Exception:
            pass
    single = int(customer.get("ng_host_id") or 0)
    ids = set([single]) if single else set()
    raw_ids = customer.get("ng_host_ids") or []
    if isinstance(raw_ids, list):
        for v in raw_ids:
            try:
                ids.add(int(v))
            except Exception:
                pass
    if ids:
        for h in _load_hosts():
            try:
                if int(h.get("store_id") or 0)==int(store_id) and int(h.get("id") or 0) in ids:
                    nm = str(h.get("name") or "").strip()
                    if nm:
                        names.add(nm)
            except Exception:
                pass
    return sorted(names)

# ===== キープ名の取得 =====
def _get_keep_name(customer: dict, store_id: int) -> str:
    name = str(customer.get("keep_liquor_name") or "").strip()
    if name:
        return name
    kid = int(customer.get("keep_liquor_id") or 0)
    if kid:
        for l in _load_liquors():
            if int(l.get("store_id") or 0)==int(store_id) and int(l.get("id") or 0)==kid:
                nm = str(l.get("name") or "").strip()
                if nm:
                    return nm
    return ""

# ===== 誕生日パーサ & 対象席の推定 =====
def _parse_birthday_to_ymd(s: str) -> str | None:
    # 全角→半角
    s = _to_ascii_digits(_norm_text(s))
    s = s.replace(".", "-").replace("/", "-")
    m = re.search(r"(\d{2,4})-(\d{1,2})-(\d{1,2})", s)
    if not m:
        return None
    y, mn, d = [int(x) for x in m.groups()]
    if y < 100:  # 2桁年を西暦化（20xx前提）
        y = 2000 + y
    try:
        return f"{y:04d}-{mn:02d}-{d:02d}"
    except Exception:
        return None

def _pick_target_seat_for_host(store_id: int, host_id: int):
    seats = [s for s in _load_seats() if int(s.get("store_id") or 0)==int(store_id)]
    # 優先：open & このホスト担当 & 姫名あり
    cand = [s for s in seats if s.get("open") and int(s.get("host_id") or 0)==int(host_id) and _nz(s.get("guest_name"))]
    if len(cand)==1:
        return cand[0]
    if len(cand)>1:
        return sorted(cand, key=lambda x: int(x.get("id") or 0))[0]
    # 次点：このホスト担当で姫名あり
    cand = [s for s in seats if int(s.get("host_id") or 0)==int(host_id) and _nz(s.get("guest_name"))]
    if cand:
        return sorted(cand, key=lambda x: int(x.get("id") or 0))[0]
    # さらに次点：openで姫名あり
    cand = [s for s in seats if s.get("open") and _nz(s.get("guest_name"))]
    if cand:
        return sorted(cand, key=lambda x: int(x.get("id") or 0))[0]
    return None

# ==== Webhook ==== #
@bp.route("/webhook", methods=["POST"])
def webhook():
    body = request.get_data(as_text=True)
    signature = request.headers.get("X-Line-Signature", "")

    if os.getenv("LINE_SKIP_SIGNATURE") == "1":
        try:
            handler.parser.parse(body)
        except Exception as e:
            print("[linebot] parser warn(dev):", e)
        return "OK"

    try:
        handler.handle(body, signature)
    except InvalidSignatureError as e:
        print("[linebot] Bad signature:", e)
        return "Bad signature", 400
    return "OK"

# ==== テキストハンドラ ==== #
@handler.add(MessageEvent, message=TextMessage)
def on_text(event: MessageEvent):
    txt_raw = (event.message.text or "")
    txt = _to_ascii_digits(_norm_text(txt_raw))
    txt_nospace = txt.replace(" ", "")
    uid = getattr(event.source, "user_id", None)

    # --- ID ---
    # --- ひも付け（登録 <店舗ID>-<ホストID>）---
    m = re.match(r"^(登録|link)\s+(\d+)\s*[-_－〜~:：]\s*(\d+)$", txt)
    if m and uid:
        store_id = int(m.group(2)); host_id = int(m.group(3))
        hosts = _load_hosts()
        target = next((h for h in hosts if int(h.get("store_id") or 0)==store_id and int(h.get("id") or 0)==host_id), None)
        if not target:
            _safe_reply(event.reply_token, f"登録失敗：店舗ID {store_id}／ホストID {host_id} が見つかりません。")
            return

        # 既存のリンクファイルを更新（従来どおり）
        links = _load_links()
        links[uid] = {"store_id": store_id, "host_id": host_id}
        _save_links(links)

        # ★ 追加：hosts.json にも LINE ユーザーID（表示名）を反映
        # 同じUIDが別ホストに付いていたら外す（重複回避）
        for h in hosts:
            try:
                same_uid = (h.get("line_user_id") == uid)
                same_host = (int(h.get("store_id") or 0)==store_id and int(h.get("id") or 0)==host_id)
                if same_uid and not same_host:
                    h["line_user_id"] = ""
            except Exception:
                pass

        target["line_user_id"] = uid
        # 可能ならプロフィール名も保存（権限があれば取得可）
        if line_bot_api:
            try:
                prof = line_bot_api.get_profile(uid)
                target["line_display_name"] = getattr(prof, "display_name", "") or ""
            except Exception:
                 pass

        _save_hosts(hosts)  # ←忘れず保存！

        _safe_reply(event.reply_token, f"登録しました。（{store_id}-{host_id}）")
        return


    # --- 紐付けチェック ---
    link = (_load_links()).get(uid or "")
    if not link:
        _safe_reply(event.reply_token, "未登録です。『登録 店舗ID-ホストID』の形式で登録してください。例）登録 2-15")
        return
    store_id = int(link.get("store_id") or 0)
    host_id  = int(link.get("host_id") or 0)
    hosts = _load_hosts()
    host = next((h for h in hosts if int(h.get("store_id") or 0)==store_id and int(h.get("id") or 0)==host_id), None)
    if not host:
        _safe_reply(event.reply_token, "登録情報が見つかりません。再度『登録 店舗ID-ホストID』で登録してください。")
        return

    # --- 出勤 ---
    if txt_nospace in ("出勤", "しゅっきん", "shukkin", "dutyon"):
        if host.get("on_duty"):
            _safe_reply(event.reply_token, "既に出勤済みです。"); return
        host["on_duty"] = True; host["last_clock_in"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_hosts(hosts)
        _safe_reply(event.reply_token, f"出勤を登録しました。（店舗{store_id}／{host.get('name','')}）")
        return

    # --- 退勤 ---
    if txt_nospace in ("退勤", "たいきん", "taikin", "dutyoff"):
        if not host.get("on_duty"):
            _safe_reply(event.reply_token, "既に退勤済みです。"); return
        host["on_duty"] = False; host["last_clock_out"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_hosts(hosts)
        _safe_reply(event.reply_token, f"退勤を登録しました。（店舗{store_id}／{host.get('name','')}）")
        return

    # --- 接客開始（席＋姫名：順不同） + 既存顧客なら NG/キープ を返信 ---
    m1 = re.match(r"^接客\s*開始\s+([A-Za-z][A-Za-z0-9]*)\s*(.*)$", txt)
    m2 = re.match(r"^([A-Za-z][A-Za-z0-9]*)\s*接客\s*開始\s*(.*)$", txt)
    if (m1 or m2):
        seat_label = (m1 and m1.group(1)) or (m2 and m2.group(1))
        guest_name = ((m1 and m1.group(2)) or (m2 and m2.group(2)) or "").strip()
        seat = _find_seat_by_label(store_id, seat_label)
        if not seat:
            _safe_reply(event.reply_token, f"席「{seat_label}」が見つかりません。"); return

        seats = _load_seats()
        for s in seats:
            if s.get("id")==seat.get("id"):
                s.setdefault("items", [])
                s["open"] = True
                s["host_id"] = host_id
                if guest_name:
                    s["guest_name"] = guest_name

                cust = None
                if guest_name:
                    cust = _find_customer_by_name(store_id, guest_name)
                    if not cust:
                        cust, _ = _upsert_customer(store_id, guest_name, host_id)

                if cust:
                    s["customer_id"] = cust.get("id")
                    _touch_visit(store_id, cust, s.get("label"), host_id, "start")

                seat = s
                break
        _save_seats(seats)

        # SSE
        _emit(store_id, "seat_update", {
            "id": seat["id"],
            "open": True,
            "guest_name": seat.get("guest_name") or "",
            "host_id": seat.get("host_id") or 0,
            "customer_id": int(seat.get("customer_id") or 0),
            "items": _seat_items_simple(seat.get("items"))
        })

        # 返信（NG/キープがあれば併記）
        guest_name = seat.get("guest_name") or guest_name
        if guest_name:
            head = f"{seat.get('label')} を接客中にしました（担当: {host.get('name','')}, 姫: {guest_name}）。"
            cust = _find_customer_by_name(store_id, guest_name)
            if cust:
                lines = [head]
                ng_names = _resolve_ng_host_names(cust, store_id)
                # 4) 複数NG対応 + 担当本人がNGに含まれる場合の注記
                if ng_names:
                    lines.append("NGホスト: " + " / ".join(ng_names))
                    # NG IDセットを生成して本人NGかチェック
                    idset = set()
                    raw_ids = cust.get("ng_host_ids") or []
                    if isinstance(raw_ids, list):
                        for v in raw_ids:
                            try:
                                idset.add(int(v))
                            except Exception:
                                pass
                    one = int(cust.get("ng_host_id") or 0)
                    if one:
                        idset.add(one)
                    if host_id in idset:
                        lines[-1] += "（※あなたはNGに含まれています）"
                elif bool(cust.get("is_ng")):
                    lines.append("NG設定: あり")
                keep_name = _get_keep_name(cust, store_id)
                if keep_name:
                    lines.append(f"キープ: {keep_name}")
                _safe_reply(event.reply_token, "\n".join(lines))
            else:
                _safe_reply(event.reply_token, head + "（顧客新規登録）")
        else:
            _safe_reply(event.reply_token, f"{seat.get('label')} を接客中にしました（担当: {host.get('name','')}）。")
        return

    # --- 誕生日（簡易形：誕生日 1995/07/23 → 自分の席の姫に設定） ---
    if txt.startswith("誕生日") and re.search(r"\d", txt):
        # まず「誕生日 A1 1995/07/23」など席指定の既存形にも対応
        seat_in_txt, rest = _find_seat_in_text(store_id, txt)
        date_str = _parse_birthday_to_ymd(txt if not rest else rest)
        if not date_str:
            _safe_reply(event.reply_token, "日付が読み取れません。例：誕生日 1995/07/23"); return

        target_seat = None
        if seat_in_txt:
            target_seat = next((s for s in _load_seats() if s.get("id")==seat_in_txt.get("id")), None)
        else:
            target_seat = _pick_target_seat_for_host(store_id, host_id)

        if not (target_seat and _nz(target_seat.get("guest_name"))):
            _safe_reply(event.reply_token, "対象の姫が特定できません。『誕生日 A1 1995/07/23』のように席を付けてください。")
            return

        guest_name = target_seat.get("guest_name")
        cust = _find_customer_by_name(store_id, guest_name)
        if not cust:
            cust, _ = _upsert_customer(store_id, guest_name, host_id)

        customers = _load_customers()
        for c in customers:
            if int(c.get("id") or 0)==int(cust.get("id") or 0):
                c["birthday"] = date_str
                cust = c
                break
        _save_customers(customers)
        _safe_reply(event.reply_token, f"姫『{cust.get('name')}』の誕生日を {date_str} に設定しました。")
        return

    # --- 給料（給与） ---
    if txt_nospace in ("給料", "給与"):
        sales = _load_sales()
        today = datetime.now().strftime("%Y-%m-%d")
        this_month = datetime.now().strftime("%Y-%m")
        s_today = [s for s in sales if int(s.get("store_id") or 0)==store_id and int(s.get("host_id") or 0)==host_id and (s.get("date")==today)]
        s_month = [s for s in sales if int(s.get("store_id") or 0)==store_id and int(s.get("host_id") or 0)==host_id and (s.get("month")==this_month)]
        comm_today = int(sum(float(s.get("commission_total") or 0) for s in s_today))
        comm_month = int(sum(float(s.get("commission_total") or 0) for s in s_month))
        _safe_reply(event.reply_token, f"【{host.get('name','')} のバック】\n・本日: ¥{comm_today:,}\n・今月: ¥{comm_month:,}")
        return

    # --- キープ（順不同：A1 ビール キープ / キープ A1 ビール など） ---
    if "キープ" in txt:
        # 席と商品を抽出
        seat, rest = _find_seat_in_text(store_id, txt)
        if not seat:
            _safe_reply(event.reply_token, "席が特定できません。例：A1 ビール キープ"); return
        rest = re.sub(r"キープ", "", rest)
        liquor, _ = _find_liquor_by_text(store_id, rest)
        if not liquor:
            _safe_reply(event.reply_token, "商品が特定できません。例：A1 ビール キープ"); return

        # 顧客を確定（席の customer_id > 名前）
        seats = _load_seats()
        seat_obj = next((s for s in seats if s.get("id")==seat.get("id")), None)
        cust = None
        if seat_obj:
            cid = int(seat_obj.get("customer_id") or 0)
            if cid:
                cust = next((c for c in _load_customers() if int(c.get("id") or 0)==cid and int(c.get("store_id") or 0)==store_id), None)
            if not cust and seat_obj.get("guest_name"):
                cust = _find_customer_by_name(store_id, seat_obj.get("guest_name"))
                if not cust:
                    cust, _ = _upsert_customer(store_id, seat_obj.get("guest_name"), host_id)
                    seat_obj["customer_id"] = cust.get("id")
                    _save_seats(seats)

        if not cust:
            _safe_reply(event.reply_token, "姫が特定できません。先に『接客 開始 席 姫』で接客開始してください。"); return

        customers = _load_customers()
        for c in customers:
            if int(c.get("id") or 0)==int(cust.get("id") or 0):
                c["keep_liquor_id"] = liquor.get("id")
                c["keep_liquor_name"] = liquor.get("name")
                c["keep_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cust = c
                break
        _save_customers(customers)

        _touch_visit(store_id, cust, seat.get("label"), host_id, "keep")
        _safe_reply(event.reply_token, f"姫『{cust.get('name')}』のキープを『{liquor.get('name')}』に設定しました（上書き）。")
        return

    # --- NG系（案内のみ：設定はPC） ---
    if txt.startswith("NG") or txt_nospace.startswith("ng") or txt.startswith("NG解除") or txt_nospace.startswith("ng解除"):
        _safe_reply(event.reply_token, "NG設定/解除はPCの顧客詳細から行ってください。\nメニュー: 顧客管理 → 顧客詳細 → NGホスト")
        return

    # --- 注文取消（順序フリー） ---
    if any(k in txt for k in ("取消", "キャンセル", "cancel")):
        seat, rest = _find_seat_in_text(store_id, txt)
        if not seat:
            _safe_reply(event.reply_token, "席が特定できませんでした。例：注文取消 A1 ビール 2"); return
        rest = re.sub(r"(取消|ｷｬﾝｾﾙ|キャンセル|cancel)", "", rest)
        liquor, rest2 = _find_liquor_by_text(store_id, rest)
        if not liquor:
            _safe_reply(event.reply_token, "商品が特定できませんでした。例：注文取消 A1 ビール 2"); return
        qty = _parse_qty(rest2, default=1)

        seats = _load_seats()
        target_seat = next((s for s in seats if s.get("id")==seat["id"]), None)
        if not target_seat:
            _safe_reply(event.reply_token, "内部エラー：席が見つかりません。"); return
        items = target_seat.setdefault("items", [])
        idx = next((i for i, it in enumerate(items) if int(it.get("liquor_id") or 0)==int(liquor.get("id"))), None)
        if idx is None or int(items[idx].get("qty") or 0) <= 0:
            _safe_reply(event.reply_token, f"{seat.get('label')} の明細に「{liquor.get('name')}」はありません。"); return

        cur_q = int(items[idx].get("qty") or 0)
        cancel_q = min(qty, cur_q)
        new_q = cur_q - cancel_q
        if new_q > 0:
            items[idx]["qty"] = new_q
        else:
            items.pop(idx)
        _save_seats(seats)

        liquors = _load_liquors()
        for l in liquors:
            if int(l.get("id") or 0)==int(liquor.get("id") or 0) and int(l.get("store_id") or 0)==store_id:
                l["stock"] = int(l.get("stock") or 0) + cancel_q
                liquor = l
                break
        _save_liquors(liquors)

        _emit(store_id, "inventory_update", {
            "id": liquor["id"], "name": liquor.get("name"),
            "sale_price": int(liquor.get("sale_price") or 0),
            "stock": int(liquor.get("stock") or 0),
        })
        _emit(store_id, "seat_update", {
            "id": target_seat["id"],
            "open": target_seat.get("open", True),
            "guest_name": target_seat.get("guest_name") or "",
            "host_id": target_seat.get("host_id") or 0,
            "customer_id": int(target_seat.get("customer_id") or 0),
            "items": _seat_items_simple(target_seat.get("items"))
        })

        # 来店ログ（取消だけでは visit_count は増やさない）
        cust = None
        cid = int(target_seat.get("customer_id") or 0)
        if cid:
            cust = next((c for c in _load_customers() if int(c.get("id") or 0)==cid and int(c.get("store_id") or 0)==store_id), None)
        elif target_seat.get("guest_name"):
            cust = _find_customer_by_name(store_id, target_seat.get("guest_name"))
        if cust:
            _touch_visit(store_id, cust, target_seat.get("label"), host_id, "order")

        _safe_reply(event.reply_token, f"{seat.get('label')} から {liquor.get('name')} x{cancel_q} を取消しました（在庫 残り {int(liquor.get('stock') or 0)}）。")
        return

    # --- 通常の注文（例：A1 ビール 2） ---
    m = re.match(r"^([A-Za-z][A-Za-z0-9]*)\s+(.+)$", txt)
    if m:
        seat_label = m.group(1); rest = m.group(2).strip()
        seat = _find_seat_by_label(store_id, seat_label)
        if not seat:
            _safe_reply(event.reply_token, f"席「{seat_label}」が見つかりません。"); return

        mqty = re.search(r"(\d+)\s*$", rest)
        if mqty:
            qty = max(1, int(mqty.group(1))); item_text = rest[:mqty.start()].strip()
        else:
            qty = 1; item_text = rest

        liquor, _ = _find_liquor_by_text(store_id, item_text)
        if not liquor:
            _safe_reply(event.reply_token, f"商品が見つかりません：「{item_text}」"); return

        cur_stock = int(liquor.get("stock") or 0)
        if cur_stock <= 0 or cur_stock < qty:
            _safe_reply(event.reply_token, "在庫がありません。"); return

        # 在庫更新
        liquors = _load_liquors()
        for l in liquors:
            if int(l.get("id") or 0)==int(liquor.get("id") or 0) and int(l.get("store_id") or 0)==store_id:
                l["stock"] = cur_stock - qty
                liquor = l; break
        _save_liquors(liquors)

        # 席明細に追加
        seats = _load_seats()
        for s in seats:
            if s.get("id")==seat.get("id"):
                s.setdefault("items", [])
                unit_price = int(liquor.get("sale_price") or 0)
                merged = False
                for it in s["items"]:
                    if int(it.get("liquor_id") or 0)==int(liquor.get("id") or 0) and int(it.get("unit_price") or 0)==unit_price:
                        it["qty"] = int(it.get("qty") or 0) + qty; merged = True; break
                if not merged:
                    s["items"].append({"liquor_id": liquor.get("id"), "name": liquor.get("name"), "qty": qty, "unit_price": unit_price})
                s["open"] = True
                if not int(s.get("host_id") or 0): s["host_id"] = host_id

                # 顧客更新（last_visit/visitログ）
                cust = None
                cid = int(s.get("customer_id") or 0)
                if cid:
                    cust = next((c for c in _load_customers() if int(c.get("id") or 0)==cid and int(c.get("store_id") or 0)==store_id), None)
                elif s.get("guest_name"):
                    cust = _find_customer_by_name(store_id, s.get("guest_name"))
                    if not cust and s.get("guest_name"):
                        cust, _ = _upsert_customer(store_id, s.get("guest_name"), host_id)
                        s["customer_id"] = cust.get("id")

                if cust:
                    _touch_visit(store_id, cust, s.get("label"), host_id, "order")

                seat = s; break
        _save_seats(seats)

        # SSE（互換: order_added も発火）
        _emit(store_id, "inventory_update", {
            "id": liquor["id"], "name": liquor.get("name"),
            "sale_price": int(liquor.get("sale_price") or 0),
            "stock": int(liquor.get("stock") or 0),
        })
        _emit(store_id, "order_added", {
            "seat_id": seat["id"],
            "item": {"name": liquor.get("name"), "qty": qty, "unit_price": int(liquor.get("sale_price") or 0)}
        })
        _emit(store_id, "seat_update", {
            "id": seat["id"],
            "open": True,
            "guest_name": seat.get("guest_name") or "",
            "host_id": seat.get("host_id") or 0,
            "customer_id": int(seat.get("customer_id") or 0),
            "items": _seat_items_simple(seat.get("items"))
        })

        _safe_reply(event.reply_token, f"{seat.get('label')} に {liquor.get('name')} x{qty} を追加しました（在庫 残り {int(liquor.get('stock') or 0)}）。")
        return


    # --- ヘルプ / フォールバック ---
    if txt_nospace in ("help", "ヘルプ", "?", "使い方"):
        _safe_reply(event.reply_token,
            "【使い方】\n"
            "・出勤 / 退勤\n"
            "・接客 開始 A1 花子 … 既存顧客なら NGホストとキープを返信\n"
            "・A1 ビール 2 … 注文／注文取消 A1 ビール 2 … 取消\n"
            "・A1 ビール キープ … キープ上書き\n"
            "・誕生日 1995/07/23 … 自分の席の姫に誕生日設定（複数席時は『誕生日 A1 1995/07/23』）\n"
            "・NG設定/解除 … PCの顧客詳細からのみ操作可能\n"
            "・給料（給与） … 今日と今月のバック合計\n"
        )
        return

    _safe_reply(event.reply_token, "コマンドが認識できません。ヘルプ と送ってください。")
