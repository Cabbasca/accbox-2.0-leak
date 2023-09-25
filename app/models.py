from app import db, login_manager
from flask_login import UserMixin
import secrets

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    api_token = db.Column(db.String(16),
                          default=secrets.token_urlsafe(16))


class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(20), nullable=False)
    app_id = db.Column(db.String(36), nullable=False)
    url_after = db.Column(db.String(100), nullable=False)

    tracks = db.relationship("Track", backref="link_tracks", lazy=True)


class Track(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(30))  # 255.255.255.255 15
    ua = db.Column(db.String(50))
    link = db.Column(db.Integer, db.ForeignKey("link.id"), nullable=False)
    time = db.Column(db.Integer, nullable=False)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, nullable=False)
    err = db.Column(db.String(40))
    refresh_token = db.Column(db.String(500))
    app_id = db.Column(db.String(36), nullable=False)
    client_secret = db.Column(db.String(50))
    access_token = db.Column(db.String(400))
    uuid = db.Column(db.String(36))
    name = db.Column(db.String(16))
    ip = db.Column(db.String(50))
    ua = db.Column(db.String(50))
    shadowed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))