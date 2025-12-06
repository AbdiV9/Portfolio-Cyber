from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()



def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Part B: secure session cookie settings
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

    db.init_app(app)
    csrf.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User

        db.drop_all()
        db.create_all()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for user in users:
            u = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"])
            db.session.add(u)
            db.session.commit()

    return app


