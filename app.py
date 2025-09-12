from flask import Flask, redirect, url_for
from config import Config
from admin import bp as admin_bp
from line_bot import bp as line_bp
try:
    from bootstrap_admin_pwd import maybe_update_admin_password
except Exception:
    maybe_update_admin_password = None

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__, static_folder="static")
    app.config.from_object(config_class)

    # Blueprints
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(line_bp, url_prefix="/line")
    
    @app.get("/healthz")
    def healthz():
        # 200を返せばOK。重い処理は入れない
        return "ok", 200, {"Content-Type": "text/plain; charset=utf-8"}
    
    @app.route("/")
    def index():
        return redirect(url_for("admin.dashboard"))

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
