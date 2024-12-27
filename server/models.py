from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True, nullable = False)
    username = db.Column(db.String, unique = True, nullable = False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref = 'users')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8')
        )

    # @validates('username')
    # def validate_username(self, key, username):
    #     if not username:
    #         raise ValueError("username cannot be empty")
    #     return username

    # def __repr__(self):
    #     return f'User {self.username}, ID: {self.id}'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String, nullable = False)
    instructions = db.Column(db.String, nullable = False)
    minutes_to_complete = db.Column(db.Integer, nullable = False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # user = db.relationship('User', back_populates = 'recipes')
    # serialize_rules = ('-user.recipes',)

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('Title is required')
        return title
    
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be present and be atleast 50 characters long")
        return instructions

    @validates('minutes_to_complete')
    def validate_minutes(self, key, minutes_to_complete):
        if minutes_to_complete < 0:
            raise ValueError("Minutes to complete must be non-negative")
        return minutes_to_complete