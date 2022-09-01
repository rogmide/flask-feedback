from flask import Flask, request, redirect, render_template, session, flash
from models import User, Tweet, db, connect_db
from forms import RegisterForm, TweetForm
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///user_auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = "123"

connect_db(app)


@app.route('/')
def home_page():
    '''Show Home Page'''

    # # Work factor is the time that the encryption is going to take to generate the hash
    # # Random string that is going to be addeed to our password
    # salt = bcrypt.gensalt()
    # # Password hash need to add b'password for some reason'
    # user_pws = b'pws123'
    # pws = bcrypt.hashpw(user_pws, salt)

    # Initialize
    # bcrypt = Bcrypt()

    # user_pws = bcrypt.generate_password_hash("pws123")
    # print('===========', user_pws)
    # isOwner = bcrypt.check_password_hash(user_pws, 'asdfasdfa')
    # print('===========', isOwner)

    # db.drop_all()
    # db.create_all()

    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Register a User in to the app'''

    form = RegisterForm()

    if form.validate_on_submit():

        name = form.username.data
        pwd = form.password.data
        user = User.register(name, pwd)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username Taken. Please pick another')
            return render_template('register.html', user_regi=form)

        session['user_id'] = user.id

        flash('Welcome! Successfully Created Your Account!', 'success')

        return redirect('/')
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
            flash(f'Welcome Back, {user.username}!', 'primary')
            return redirect('/tweets')
        else:
            form.username.errors = ['Invalid username/password']

    return render_template('login.html', user_regi=form)


@app.route('/secret')
def get_secret_page():

    if 'user_id' not in session:
        flash('You mush be logged to get here', 'danger')
        return redirect('/')
    else:
        return render_template('secret.html')


@app.route('/tweets', methods=['GET', 'POST'])
def get_tweets_page():
    '''Check if user is login and render tweets pages'''

    if 'user_id' not in session:
        flash('Please login first!', 'danger ')
        return redirect('/')

    form = TweetForm()

    all_tweets = Tweet.query.all()

    if form.validate_on_submit():
        text = form.text.data
        new_tweet = Tweet(text=text, user_id=session['user_id'])
        db.session.add(new_tweet)
        db.session.commit()
        flash('Tweet is Created', 'info ')
        return redirect('/tweets')

    return render_template('tweets.html', form=form, all_tweets=all_tweets)


@app.route('/tweets/<int:id>', methods=['POST'])
def delete_tweet(id):
    '''Delete Tweet for a user'''

    if 'user_id' not in session:
        flash('Plz login first', 'danger')
        return redirect('/login')

    tweet = Tweet.query.get_or_404(id)

    if tweet.user_id == session['user_id']:
        db.session.delete(tweet)
        db.session.commit()
        flash('Tweet Deleted', 'info')
        return redirect('/tweets')
    flash('Is not your tweet to delete', 'danger')
    return redirect('/tweets')


@app.route('/logout')
def logout():
    '''logout user from the app'''

    # just remove the user_id from the session
    session.pop('user_id', None)
    flash('Goodbye', 'info')
    return redirect('/')
