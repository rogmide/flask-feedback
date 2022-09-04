from crypt import methods
import email
from flask import Flask, request, redirect, render_template, session, flash, Response, abort
from flask_mail import Mail, Message
from models import User, Feedback, db, connect_db
from forms import RegisterForm, TweetForm, UserSignInForm, FeedbackForm, ResetPasswordForm, NewPosswordForm
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from hidden_stuff import EMAIL_SECRET_KEY, MAIL_PWD, MAIL_USER
from flask_bcrypt import Bcrypt
import os

bcrypt = Bcrypt()

app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback_db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'postgresql:///feedback_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'jashdf734625986asdfglkhjasdfasdlfjkg')


# Mail Config
app.config['MAIL_SERVER'] = 'smtp.mail.yahoo.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# If your using SSL
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = MAIL_USER
app.config['MAIL_PASSWORD'] = MAIL_PWD
app.config['MAIL_DEFAULT_SENDER'] = 'rogmide@yahoo.com'


mail = Mail(app)

connect_db(app)


@app.route('/')
def home_page():
    '''Show Home Page'''

    db.drop_all()
    db.create_all()

    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Register a User in to the app'''

    form = UserSignInForm()

    if 'user_name' in session:
        flash('Your Already Login', 'info')

        return redirect('/')

    if form.validate_on_submit():

        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        user = User.register(username, password, email, first_name, last_name)
        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username Taken. Please pick another')
            return render_template('register.html', user_regi=form)

        session['user_id'] = user.id
        session['user_name'] = user.username

        flash('Welcome! Successfully Created Your Account!', 'success')

        return redirect('/secret')
    else:

        return render_template('register.html', user_regi=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Register a User in to the app'''

    form = RegisterForm()

    if 'user_name' in session:
        flash('Your Already Login', 'info')

        return redirect('/')

    if form.validate_on_submit():

        name = form.username.data
        pwd = form.password.data

        user = User.authenticate(name, pwd)

        if user:
            session['user_id'] = user.id
            session['user_name'] = user.username
            flash(f'You made it!, {user.username}!', 'primary')
            return redirect('/secret')
        else:
            form.username.errors = ['Invalid username/password']

    return render_template('login.html', user_regi=form)


@app.route('/password_reset', methods=['GET', 'POST'])
def reset_password():
    '''Handle Send Email to user to reset password'''

    form = ResetPasswordForm()

    if form.validate_on_submit():
        flash('Reset request send. Check your Email', 'info')
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_mail(user)
            return redirect('/login')

    return render_template('reset_password.html', form=form)


@app.route('/password_reset/<token>/<user_mail>', methods=['GET', 'POST'])
def reset_token(token, user_mail):
    '''Verefy that the token is valid'''

    u = User.query.filter_by(email=user_mail).first()
    user = u.check_token(token)

    if not user[0]:
        flash('Expire Token!', 'danger')
        return redirect('/password_reset')

    form = NewPosswordForm()
    if form.validate_on_submit():
        hashed_pwd = bcrypt.generate_password_hash(
            form.new_password.data).decode('utf-8')
        user[1].password = hashed_pwd
        db.session.add(user[1])
        db.session.commit()
        flash('Password Changed!', 'success')
        return redirect('/login')

    return render_template('change_password.html', form=form)


def send_mail(user):
    '''Send Email To a User'''

    token = user.get_token()
    msg = Message('Password Reset Request',
                  recipients=[user.email])
    msg.body = f''' To reset your password. Please follow the link below.
     
    http://127.0.0.1:5000/password_reset/{token}/{user.email}" - Reset Password Link!
    
    If you didn't send a password rest request. Please ignore this message.
    '''

    mail.send(msg)


@app.route('/users/<username>', methods=['GET', 'POST'])
def get_user(username):
    '''Get User and SHow information on Page'''

    if 'user_id' not in session:
        abort(401)
    else:
        user = User.query.filter_by(username=username).first()

        if user.is_admin:
            users = User.query.all()
            feedbacks = Feedback.query.all()
            return render_template('user_info.html', user=user, users=users, feedbacks=feedbacks)

        return render_template('user_info.html', user=user)


@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    '''Get User and SHow information on Page'''

    if 'user_id' not in session:
        abort(401)

    else:
        user = User.query.filter_by(username=username).first()
        db.session.delete(user)
        db.session.commit()

        session.pop('user_id', None)
        session.pop('user_name', None)

        flash('User Account is Cancel', 'info')

        return redirect('/')


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def show_feedback_form(username):
    '''Show form to add new feedback for the user that is login'''

    form = FeedbackForm()

    if 'user_id' not in session:
        abort(401)

    else:

        if form.validate_on_submit():

            title = form.title.data
            content = form.content.data
            imagen_url = form.imagen_url.data if form.imagen_url.data else None

            t = Feedback.add_feedback(username, title, content, imagen_url)
            db.session.add(t)
            db.session.commit()

            flash('Feedback Created!', 'info')
            return redirect(f'/users/{username}')

    return render_template('feedback_form.html', form=form)


@app.route('/feedback/<int:id>/update', methods=['GET', 'POST'])
def show_update_feedback(id):
    '''Show form to get and updated a feedback'''

    feedback = Feedback.query.get_or_404(id)
    form = FeedbackForm(obj=feedback)

    if 'user_id' not in session:
        abort(401)

    else:

        if form.validate_on_submit():

            title = form.title.data
            content = form.content.data
            imagen_url = form.imagen_url.data if form.imagen_url.data else None

            feedback.title = title
            feedback.content = content
            feedback.imagen_url = imagen_url

            db.session.add(feedback)
            db.session.commit()

            username = session['user_name']

            flash('Feedback Is Updated!', 'info')
            return redirect(f'/users/{username}')

    return render_template('feedback_updates.html', form=form)


@app.route('/feedback/<int:id>/delete', methods=['POST'])
def delete_feedback(id):
    '''Delete a Feedback for a User'''

    if 'user_id' not in session:
        abort(401)

    feedback = Feedback.query.get_or_404(id)
    db.session.delete(feedback)
    db.session.commit()

    flash('Feedback is deleted!', 'info')
    username = session['user_name']
    return redirect(f'/users/{username}')


@app.route('/secret')
def get_secret_page():
    '''Show Secret Page for a user that is login'''

    if 'user_id' not in session:
        abort(401)
    else:
        return render_template('secret.html')


@app.route('/logout', methods=['POST'])
def logout():
    '''logout user from the app'''

    # just remove the user_id from the session
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('Goodbye', 'info')
    return redirect('/')


@app.errorhandler(404)
def not_found(e):
    '''404 Error Handeling'''

    return render_template("404.html")


@app.errorhandler(401)
def custom_401(e):
    '''401 Error Handeling'''
    return render_template("401.html")
