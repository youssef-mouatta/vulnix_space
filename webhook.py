import hmac
import hashlib
from flask import Blueprint, request, jsonify
from utils.logger import get_logger
from config import Config
from models import db, User

logger = get_logger(__name__)
webhook_bp = Blueprint('webhook', __name__)

@webhook_bp.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    if not sig_header or not Config.STRIPE_WEBHOOK_SECRET:
        return "Missing signature or secret config", 400

    # Note: In production you would use stripe python lib: 
    # stripe.Webhook.construct_event(payload, sig_header, Config.STRIPE_WEBHOOK_SECRET)
    
    # We simulate handling the event payload here:
    try:
        event = request.get_json(silent=True) or {}
        event_type = event.get('type')
        
        logger.info(f"Received webhook event: {event_type}")

        if event_type == 'checkout.session.completed':
            session = event['data']['object']
            customer_email = session.get('customer_details', {}).get('email')
            # BUG FIX: Look up by email column, not username (username != email)
            if customer_email:
                user = User.query.filter_by(email=customer_email).first()
                if user:
                    user.tier = "Pro" # or map based on exact checkout metadata
                    db.session.commit()
                    logger.info(f"Upgraded user {user.id} to Pro")

        return jsonify(success=True), 200

    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify(error=str(e)), 400
