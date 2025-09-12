import os, json, pathlib
from flask import Flask, redirect, url_for
from config import Config
from admin import bp as admin_bp
from line_bot import bp as line_bp
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
SETTINGS_JSON = os.path.join(INSTANCE_DIR, "settings.json")

def _bootstrap_admin_password():
    """
    Render 環境変数 ADMIN_PASSWORD を読み取り、
    instance/settings.json の admin_password を（scrypt で）更新する。
    実行ログは [adminpwd] で始まる。
    """
    try:
        pathlib.Path(INSTANCE_DIR).mkdir(parents=True, exist_ok=True)
        settings = {}
        if os.path.exists(SETTINGS_JSON):
            try:
                with open(SETTINGS_JSON, "r", encoding="utf-8") as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}

        env_pw = os.getenv("ADMIN_PASSWORD")  # ← Render の Environment で設定
        print("[adminpwd] bootstrap executed", flush=True)
        if env_pw:
            hashed = generate_password_hash(env_pw, method="scrypt")
            settings["admin_password"] = hashed
            with open(SETTINGS_JSON, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
            print(f"[adminpwd] updated settings.json at {SETTINGS_JSON}", flush=True)
        else:
            print("[adminpwd] ADMIN_PASSWORD not set; skipped update", flush=True)
    except Exception as e:
        print("[adminpwd] bootstrap error:", e, flush=True)

def create_app(config_class=Config) -> Flask:
    # 起動直後に必ず実行（Render でもローカルでも）
    _bootstrap_admin_password()

    app = Flask(__name__, static_folder="static")
    app.config.from_object(config_class)

    # Blueprints
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(line_bp, url_prefix="/line")

    @app.route("/")
    def index():
        return redirect(url_for("admin.dashboard"))

    # Render のヘルスチェック
    @app.route("/healthz")
    def healthz():
        return "ok", 200

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
