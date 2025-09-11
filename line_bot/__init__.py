from flask import Blueprint
bp = Blueprint("line_bot", __name__)
from . import routes  # noqa
# line_bot/__init__.py
from .routes import bp  # これだけでOK（アプリ側から import しやすくする）
