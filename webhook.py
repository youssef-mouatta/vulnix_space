import stripe
from flask import Blueprint, jsonify, request

from config import Config
from models import User, db
from utils.logger import get_logger

logger = get_logger(__name__)
webhook_bp = Blueprint("webhook", __name__)


def _tier_from_session(session: dict) -> str:
    """
    Expect Stripe Checkout Session metadata, e.g. metadata[tier]=Pro|Business
    (configure in Stripe Dashboard or when creating the session).
    """
    md = session.get("metadata") or {}
    tier = (md.get("tier") or md.get("plan") or "Pro").strip()
    if tier not in ("Pro", "Business"):
        return "Pro"
    return tier


@webhook_bp.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(cache=False, as_text=False)
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = Config.STRIPE_WEBHOOK_SECRET

    if not sig_header or not webhook_secret:
        return jsonify(error="Missing signature or webhook secret"), 400

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError:
        logger.warning("Stripe webhook: invalid payload")
        return jsonify(error="invalid payload"), 400
    except stripe.error.SignatureVerificationError as exc:
        logger.warning("Stripe webhook: signature verification failed: %s", exc)
        return jsonify(error="invalid signature"), 400

    event_type = event.get("type")
    logger.info("Stripe webhook event: %s", event_type)

    try:
        if event_type == "checkout.session.completed":
            session = event.get("data", {}).get("object") or {}
            customer_email = (session.get("customer_details") or {}).get("email")
            tier = _tier_from_session(session)

            if customer_email:
                user = User.query.filter_by(email=customer_email.lower()).first()
                if user:
                    user.tier = tier
                    db.session.commit()
                    logger.info("Upgraded user %s to %s via Stripe", user.id, tier)

        return jsonify(success=True), 200
    except Exception as e:
        logger.error("Stripe webhook handler error: %s", e)
        db.session.rollback()
        return jsonify(error=str(e)), 500
