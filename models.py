from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=True)  # Used for Stripe webhook lookup
    password = db.Column(db.String(150), nullable=False)
    tier = db.Column(db.String(20), default='Free')
    api_key = db.Column(db.String(100), unique=True, nullable=True)
    scans = db.relationship('ScanResult', backref='user', lazy=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    score = db.Column(db.String(10), nullable=False)
    issues_json = db.Column(db.Text, nullable=False) # Store issues as JSON string
    explanation_json = db.Column(db.Text, nullable=False) # Store explanation as JSON string
    is_public = db.Column(db.Boolean, default=False)
    date_scanned = db.Column(db.DateTime, default=datetime.utcnow)
