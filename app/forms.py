from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from flask_login import login_user
from app import models, bcrypt

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = models.User.query.filter_by(
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
        user = models.User.query.filter_by(username=self.username.data).first()
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
        if models.Link.query.filter(models.Link.app_id == app_id.data).first():
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
