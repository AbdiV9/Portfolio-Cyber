from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

    # Option B: this stores the hashed password
    password = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.role = role
        self.bio = bio
        self.password = generate_password_hash(password)   # HASH PASSWORD

    def check_password(self, password):
        return check_password_hash(self.password, password)  # CHECK HASH

    def set_password(self, new_password):
        self.password = generate_password_hash(new_password)  # UPDATE HASH





