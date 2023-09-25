from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

app = Flask(__name__, template_folder='../templates', static_folder='../static')

with app.app_context():
    # this is so the config is not icluded
    app.config.from_pyfile("../instance/config.py")

    db = SQLAlchemy(app)
    bcrypt = Bcrypt(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"