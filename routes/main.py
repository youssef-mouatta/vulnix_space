from flask import Blueprint, render_template

main_bp = Blueprint('main', __name__)

@main_bp.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@main_bp.route("/pricing")
def pricing():
    return render_template("pricing.html")

@main_bp.route("/contact")
def contact():
    return render_template("contact.html")

@main_bp.route("/thank-you")
def thank_you():
    return render_template("thank_you.html")
