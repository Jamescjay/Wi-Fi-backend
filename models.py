from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Admin(db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

class Hotspot(db.Model):
    __tablename__ = 'hotspots'
    hotspot_id = db.Column(db.Integer, primary_key=True)
    hotspot_name = db.Column(db.String, nullable=False)
    router_mac = db.Column(db.String, unique=True, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String, nullable=False)
    subscription = db.Column(db.String, nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
    hotspot_id = db.Column(db.Integer, db.ForeignKey('hotspots.hotspot_id'), nullable=False)

class Payment(db.Model):
    __tablename__ = 'payments'
    payment_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    hotspot_id = db.Column(db.Integer, db.ForeignKey('hotspots.hotspot_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Bonus(db.Model):
    __tablename__ = 'bonuses'
    bonus_id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
