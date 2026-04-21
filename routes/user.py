from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user
from models import ScanResult

user_bp = Blueprint('user', __name__)

@user_bp.route("/api/user/profile")
@login_required
def get_user_profile():
    """
    Returns user profile and subscription plan.
    Helpful for decoupled frontend interfaces.
    """
    return jsonify({
        "username": current_user.username,
        "tier": current_user.tier,
        "id": current_user.id
    })

@user_bp.route("/dashboard")
@login_required
def dashboard():
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.date_scanned.desc()).all()
    return render_template("dashboard.html", scans=scans)
