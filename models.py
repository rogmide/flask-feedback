from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()


def connect_db(app):
    db.app = app
    db.init_app(app)

# Model go Below


class User(db.Model):
    "Site user."

    __tablename__ = "users"

    id = db.Column(db.Integer,
                   primary_key=True,
                   autoincrement=True)

    username = db.Column(db.Text,
                         nullable=False,
                         unique=True)

    password = db.Column(db.Text,
                         nullable=False)

    @classmethod
    def register(cls, username, pwd):
        '''Register a user to the DB with hash password'''

        hashed = bcrypt.generate_password_hash(pwd)
        # turn bytestring into normal (unicode utf8) string
        hashed_utf8 = hashed.decode('utf8')

        # return instance of user w/username and hashed pwd
        return cls(username=username, password=hashed_utf8)

    @classmethod
    def authenticate(cls, username, pwd):
        '''Validate that the user exists in the db with correct password

        return user if valid or False
        '''

        u = User.query.filter_by(username=username).first()

        if u and bcrypt.check_password_hash(u.password, pwd):
            # return intance of user
            return u

        else:
            return False


class Tweet(db.Model):

    __tablename__ = 'tweets'

    id = db.Column(db.Integer,
                   primary_key=True,
                   autoincrement=True)

    text = db.Column(db.Text,
                     nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('User', backref='tweets')
