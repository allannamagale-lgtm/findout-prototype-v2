from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_mail import Mail
from flask import session

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
mail = Mail()
talisman = Talisman()


def user_or_ip():
    """Rate-limit key: per-user if logged in, else per-IP."""
    uid = session.get("user_id")
    return f"user:{uid}" if uid else f"ip:{get_remote_address()}"


limiter = Limiter(
    key_func=user_or_ip,
    default_limits=["500 per day", "120 per hour"],
    storage_uri="memory://",  # TODO: switch to redis:// in production
)