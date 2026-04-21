from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

def require_plan(*allowed_plans):
    """
    Decorator to restrict access to features based on the User's subscription tier.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.tier not in allowed_plans:
                flash(f"This feature requires one of the following plans: {', '.join(allowed_plans)}.")
                return redirect(url_for('main.pricing'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
