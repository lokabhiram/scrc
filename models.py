from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(80), nullable=False)  # 'influencer' or 'sponsor'

    __mapper_args__ = {
        'polymorphic_identity': 'user',
        'polymorphic_on': user_type
    }

class Influencer(User):
    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    platform_presence = db.Column(db.String(200), nullable=True)

    __mapper_args__ = {
        'polymorphic_identity': 'influencer',
    }

class Sponsor(User):
    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    industry = db.Column(db.String(100), nullable=True)

    __mapper_args__ = {
        'polymorphic_identity': 'sponsor',
    }

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), nullable=True)  # Store image URL or path
    niche = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(100), nullable=False) 
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)

    sponsor = db.relationship('Sponsor', backref=db.backref('campaigns', lazy=True))
