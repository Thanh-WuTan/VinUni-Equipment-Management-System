from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from datetime import datetime, date
from hashlib import md5

ACCESS = {
    'guest': 0,
    'research_assistant': 1,
    'project_pi':2,
    'lab_manager':3,
    'admin': 4
}

CATEGORY = {
    0: 'guest',
    1: 'research_assistant',
    2: 'project_pi',
    3: 'lab_manager',
    4: 'admin'
}


class User_role_change_request(db.Model):
    __tablename__ = 'user_role_change_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_name = db.Column(db.String)
    new_role = db.Column(db.Integer)
    date_added = db.Column(db.String, default=str(date.today()))
    
    def __init__(self, user_id, user_name, new_role):
        self.user_name = user_name
        self.new_role = new_role
        self.user_id = user_id

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    user_name = db.Column(db.String(150), unique=True)
    access = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    requests =  db.relationship('User_role_change_request')
    
    def __init__(self, email, first_name, last_name, user_name, access, password):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name 
        self.user_name = user_name
        self.access = access
        self.password = password
        
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)



class Equipment(db.Model): 
    __tablename__ = 'equipment'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, unique=True)
    type = db.Column(db.Text)
    owner = db.Column(db.Text)
    location = db.Column(db.Text)
    status = db.Column(db.Integer) #available to borrow or not , being archived or not, being borrowed or not
    description = db.Column(db.Text)
    working_condition = db.Column(db.String)
    comments = db.Column(db.Text)
    
    def __init__(self, name, type, owner, location, status, description, working_condition, comments):
        self.name = name
        self.type = type
        self.owner = owner
        self.location = location
        self.status = status
        self.description = description
        self.working_condition = working_condition
        self.comments = comments
    
        
class Image(db.Model):
    __tablename__ = 'image'
    id = db.Column(db.Integer, primary_key=True)
    equip_id = db.Column(db.Integer, db.ForeignKey('equipment.id'))
    filepath = db.Column(db.String)
    
    def __init__(self, equip_id, filepath):
        self.equip_id = equip_id
        self.filepath = filepath
    
class Request(db.Model):
    __tablename__ = 'request'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String, db.ForeignKey('user.user_name'))
    equip_name = db.Column(db.String, db.ForeignKey('equipment.name'))
    term_of_use = db.Column(db.Text)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    date_requested = db.Column(db.DateTime, default=datetime.utcnow())
    status = db.Column(db.Integer) 
    comments = db.Column(db.Text)
 