import json
from flask import Blueprint, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, ScanResult
from scanner import scan_website, is_scan_failed, has_real_issues
from utils.logger import get_logger
from utils.security import is_valid_url, normalize_url
from payments import PaymentService

logger = get_logger(__name__)
scan_bp = Blueprint('scan', __name__)

@scan_bp.route("/scan", methods=["POST"])
@login_required
def perform_scan():
    url = normalize_url(request.form.get("url", ""))

    if not url or not is_valid_url(url):
        flash("Please enter a valid, safe URL.")
        return redirect(url_for('user.dashboard'))

    # Limit Enforcement via PaymentService
    scans_count = ScanResult.query.filter_by(user_id=current_user.id).count()
    if not PaymentService.within_scan_limit(current_user.tier, scans_count):
        flash("You have reached your limit. Please upgrade your plan!")
        return redirect(url_for('main.pricing'))

    issues, score, risk_level, is_limited, network_info = scan_website(url)

    # Store full findings so upgrades unlock historical reports; tier gating is in report view.
    # Detect scan failures
    failed = is_scan_failed(issues)
    real_vulns = has_real_issues(issues)

    new_scan = ScanResult(
        user_id=current_user.id,
        url=url,
        score=score,
        issues_json=json.dumps(issues),
        explanation_json=json.dumps({
            "scan_failed": failed,
            "is_limited":  is_limited,
            "has_issues":  real_vulns,
            "risk_level":  risk_level,
            "network_info": network_info,
        })
    )
    db.session.add(new_scan)
    db.session.commit()

    logger.info(
        f"User {current_user.id} ({current_user.tier}) scanned {url} | issues={len(issues)}"
    )

    return redirect(url_for('report.report', scan_id=new_scan.id))
