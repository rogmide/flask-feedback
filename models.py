from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

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
