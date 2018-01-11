from app import db
from datetime import datetime, timedelta


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    created = db.Column(db.DateTime, default=datetime.utcnow)


class Weights(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity = db.Column(db.String(50))
    weight = db.Column(db.Integer)
    units = db.Column(db.String(10))
    reps = db.Column(db.Integer)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.ForeignKey(User.id))


class Times(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity = db.Column(db.String(50))
    time = db.Column(db.DateTime())
    distance = db.Column(db.Integer)
    units = db.Column(db.String(10))
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.ForeignKey(User.id))