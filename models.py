from email.policy import default
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import TimedSerializer
from hidden_stuff import EMAIL_SECRET_KEY

db = SQLAlchemy()
bcrypt = Bcrypt()


def connect_db(app):
    db.app = app
    db.init_app(app)


# Model go Below


class User(db.Model):
    '''User model for the site'''

    __tablename__ = "users"

    id = db.Column(db.Integer,
                   primary_key=True,
                   autoincrement=True)

    is_admin = db.Column(db.Boolean,
                         nullable=False,
                         default=False)

    username = db.Column(db.Text,
                         nullable=False,
                         unique=True)

    password = db.Column(db.Text,
                         nullable=False)

    email = db.Column(db.String(50),
                      nullable=False,
                      unique=True)

    first_name = db.Column(db.String(30),
                           nullable=False,
                           unique=True)

    last_name = db.Column(db.String(30),
                          nullable=False,
                          unique=True)

    def get_token(self):
        '''Create a Toke for a User'''

        # CREATE A TOKEN TO THE USER
        serial = TimedSerializer(EMAIL_SECRET_KEY, 'confirmation')
        return serial.dumps(self.id)

    def check_token(self, token, max_age=300):
        '''Check that the token is valid'''
        serial = TimedSerializer(EMAIL_SECRET_KEY, 'confirmation')
        return [serial.loads(token, max_age=max_age) == self.id, self]

    def __repr__(self):
        '''Better Representation of the class'''
        u = self
        return f'<User id={u.id} name={u.first_name} last_name={u.last_name} email={u.email}>'

    @property
    def fullname(self):
        '''Property to acces to the user full name'''
        return '{} {}'.format(self.first_name, self.last_name)

    @fullname.setter
    def fullname(self, name):
        '''Set User full name variables first, middle and last name
        Note: middle name can be empty
        '''
        self.first_name, self.last_name = name.split(' ')

    @fullname.deleter
    def fullname(self, name):
        '''Set User full name variables first, middle and last name to None
        Note: middle name can be empty
        '''
        self.first_name, self.last_name = None, None

    @classmethod
    def register(cls, username, pwd, email, first_name, last_name):
        '''Register a user to the DB with hash password'''

        hashed = bcrypt.generate_password_hash(pwd)
        # turn bytestring into normal (unicode utf8) string
        hashed_utf8 = hashed.decode('utf8')

        # return instance of user w/username and hashed pwd
        return cls(username=username, password=hashed_utf8, email=email, first_name=first_name, last_name=last_name)

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

    # this relationship work to delete on cascade
    # feedbacks back_populates user
    feedbacks = db.relationship(
        "Feedback", back_populates="user", passive_deletes=True)


class Feedback(db.Model):
    '''Feedback Model'''

    __tablename__ = "feedbacks"

    id = db.Column(db.Integer,
                   primary_key=True,
                   autoincrement=True)

    title = db.Column(db.String(100),
                      nullable=False,)

    content = db.Column(db.Text,
                        nullable=False,)

    imagen_url = db.Column(db.Text,
                           nullable=False,
                           default='https://images.unsplash.com/photo-1473830394358-91588751b241?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80')

    username = db.Column(db.Text, db.ForeignKey(
        'users.username', ondelete='CASCADE'))

    @classmethod
    def add_feedback(cls, username, title, content, imagen_url):
        '''Add a feedback for a user'''

        return cls(title=title, content=content, username=username, imagen_url=imagen_url)

    # this relationship work to delete on cascade
    # user is back_populates feedbacks
    user = db.relationship('User', back_populates="feedbacks")
