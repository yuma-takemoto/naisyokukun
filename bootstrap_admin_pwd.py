# bootstrap_admin_pwd.py
import os, json
from pathlib import Path
from werkzeug.security import generate_password_hash

INSTANCE_DIR = Path(__file__).resolve().parent / "instance"
SETTINGS_JSON = INSTANCE_DIR / "settings.json"

def maybe_update_admin_password():
    pwd = os.getenv("ADMIN_PASSWORD")
    if not pwd:
        return
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    data = {}
    if SETTINGS_JSON.exists():
        try:
            data = json.loads(SETTINGS_JSON.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    # scrypt でハッシュ（Flask/Werkzeug の check_password_hash と互換）
    data["admin_password"] = generate_password_hash(pwd, method="scrypt")
    SETTINGS_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
