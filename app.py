from crypt import methods
from flask import Flask, request, redirect, render_template, session, flash
from models import User, Feedback, db, connect_db
from forms import RegisterForm, TweetForm, UserSignInForm, FeedbackForm
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = "123"

connect_db(app)


@app.route('/')
def home_page():
    '''Show Home Page'''

    # db.drop_all()
    # db.create_all()

    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Register a User in to the app'''

    form = UserSignInForm()

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


@app.route('/users/<username>', methods=['GET', 'POST'])
def get_user(username):
    '''Get User and SHow information on Page'''

    if 'user_id' not in session:
        flash('You mush be logged to get here', 'danger')
        return redirect('/')
    else:
        user = User.query.filter_by(username=username).first()
        return render_template('user_info.html', user=user)


@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    '''Get User and SHow information on Page'''

    if 'user_id' not in session:
        flash('You mush be logged to get here', 'danger')
        return redirect('/')
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
        flash('You mush be logged to get here', 'danger')
        return redirect('/')
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
        flash('You mush be logged to get here', 'danger')
        return redirect('/')
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
        flash('You mush be logged to get here', 'danger')
        return redirect('/')

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
        flash('You mush be logged to get here', 'danger')
        return redirect('/')
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
