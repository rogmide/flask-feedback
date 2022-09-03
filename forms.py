from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired, Email


class RegisterForm(FlaskForm):
    """Form for registering a user."""

    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])


class LoginForm(FlaskForm):
    """Form for registering a user."""

    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])


class TweetForm(FlaskForm):
    '''For for the user to add tweet'''

    text = StringField('Tweet Text', validators=[InputRequired()])


class UserSignInForm(FlaskForm):
    '''For use for user to sign in'''

    username = StringField("Username", validators=[InputRequired()])
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired()])
    first_name = StringField("First Name", validators=[InputRequired()])
    last_name = StringField("Last Name", validators=[InputRequired()])


class FeedbackForm(FlaskForm):
    '''For use for user to sign in'''

    title = StringField("Title", validators=[InputRequired()])
    content = TextAreaField("Content", validators=[InputRequired()])
    imagen_url = StringField("Image Url")


class ResetPasswordForm(FlaskForm):
    '''For use for user to sign in'''

    email = StringField("Email", validators=[InputRequired(), Email()])

class NewPosswordForm(FlaskForm):
    '''For use for user to sign in'''

    new_password = PasswordField("New Password", validators=[InputRequired()])
