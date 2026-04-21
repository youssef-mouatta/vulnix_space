import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user
from models import db, ScanResult
from ai_service import chat_about_scan

report_bp = Blueprint('report', __name__)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_meta(scan: ScanResult) -> dict:
    """Safely parse the explanation_json metadata stored at scan time."""
    try:
        return json.loads(scan.explanation_json) or {}
    except (ValueError, TypeError):
        return {}

def _guard_ai(scan: ScanResult):
    """
    Returns a JSON error response if the scan should NOT trigger AI calls,
    or None if the call is allowed to proceed.
    """
    meta = _get_meta(scan)

    if meta.get("scan_failed"):
        return jsonify({
            "error": "scan_failed",
            "message": (
                "⚠️ Scan Failed\n\n"
                "We couldn't analyze this website.\n\n"
                "Possible reasons:\n"
                "* Server not responding\n"
                "* Firewall blocking requests\n"
                "* Timeout occurred\n\n"
                "👉 Try again later or test another website."
            )
        }), 503

    return None  # All other cases (Limited, Secure, Valid) go to AI


# ─── Routes ───────────────────────────────────────────────────────────────────

@report_bp.route("/report/<int:scan_id>")
def report(scan_id):
    scan = db.get_or_404(ScanResult, scan_id)
    if not scan.is_public:
        if not current_user.is_authenticated:
            flash("Please log in to view this private report.")
            return redirect(url_for('auth.login', next=request.path))
        if scan.user_id != current_user.id:
            flash("Unauthorized or Private Report.")
            return redirect(url_for('user.dashboard'))

    from services.priority_engine import prioritize
    from ai_service import safe_generate, generate_summary, _format_input

    issues = json.loads(scan.issues_json)
    meta   = _get_meta(scan)
    
    # Sort and prioritize issues
    issues = prioritize(issues)
    
    # Generate AI Insight summary using real AI pipeline
    real_finds = [i for i in issues if i.get("classification") in ("REAL_RISK", "SECURITY_WEAKNESS")]
    if real_finds:
        formatted_input = _format_input(real_finds)
        raw_str = json.dumps(real_finds)
        ai_summary = safe_generate(generate_summary, formatted_input, raw_str) or "Attacker may exploit identified vulnerabilities."
    else:
        ai_summary = "Secure Target Environment. No exploited paths or significant security weaknesses identified."

    user_tier = current_user.tier if current_user.is_authenticated else "free"

    return render_template(
        "report.html",
        scan=scan,
        issues=issues,
        score=scan.score,
        risk=meta.get("risk_level", "Unknown"),
        target=scan.url,
        ai_summary=ai_summary,
        meta=meta,
        network_info=meta.get("network_info", {"ip": None, "open_ports": []}),
        scan_failed=meta.get("scan_failed", False),
        is_limited=meta.get("is_limited", False),
        has_issues=meta.get("has_issues", True),
        user_tier=user_tier.lower()
    )


@report_bp.route("/api/share/<int:scan_id>", methods=["POST"])
def toggle_share(scan_id):
    scan = db.get_or_404(ScanResult, scan_id)
    if not current_user.is_authenticated or scan.user_id != current_user.id:
        return {"error": "Unauthorized"}, 403

    scan.is_public = not scan.is_public
    db.session.commit()
    return {"is_public": scan.is_public, "message": "Visibility updated"}


@report_bp.route("/api/chat/<int:scan_id>", methods=["POST"])
def report_chat(scan_id):
    scan = db.get_or_404(ScanResult, scan_id)
    if not scan.is_public:
        if not current_user.is_authenticated or scan.user_id != current_user.id:
            return {"error": "Unauthorized"}, 403

    # Block AI if scan failed or no real vulnerabilities
    blocked = _guard_ai(scan)
    if blocked:
        return blocked

    payload = request.get_json(silent=True) or {}
    user_message = (payload.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "missing_message", "message": "A chat message is required."}), 400

    meta = _get_meta(scan)
    user_tier = current_user.tier if current_user.is_authenticated else "free"
    return jsonify(chat_about_scan(scan.url, scan.issues_json, user_message, meta=meta, user_tier=user_tier))
