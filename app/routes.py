from flask import (request, render_template, redirect, url_for,session, Blueprint, flash, abort)
from sqlalchemy import text
from app import db
from app.models import User

# Part A: Import validation + sanitisation utilities
from app.validation import (
    validate_username,
    validate_string,
    validate_role,
    sanitise_html
)

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('home.html')


@main.route('/login', methods=['GET', 'POST'])
@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            # Part A: Validate email/username and password format
            username = validate_username(request.form.get('username'))
            password = validate_string(request.form.get('password'), "Password", min_len=10, max_len=128)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('login.html'), 400

        # Part C:  ORM lookup replaces unsafe SQL select
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):

            # Part B: Renew session to prevent session fixation
            session.clear()

            # Part B: Store minimal authenticated info
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio

            return redirect(url_for('main.dashboard'))

        flash('Login credentials are invalid, please try again', 'error')

    return render_template('login.html')



@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', username=session['user'], bio=session.get('bio', ''))
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Part A: validate all input fields
            username = validate_username(request.form.get('username'))
            password = validate_string(request.form.get('password'), "Password", min_len=10, max_len=128)
            role = validate_role(request.form.get('role', 'user'))
            bio = sanitise_html(request.form.get('bio', ""), max_len=500)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('register.html'), 400

        # Part A: reject duplicate accounts
        if User.query.filter_by(username=username).first():
            flash('An account with that email already exists.', 'error')


        # Part B: password is hashed inside the User model constructor
        # Part C :ORM insert replaces unsafe SQL
        new_user = User(username=username,password=password, role=role,bio=bio)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')



@main.route('/admin-panel')
def admin():
    if session.get('role') != 'admin':
        abort(403)
    return render_template('admin.html')

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main.route('/moderator')
def moderator():
    if session.get('role') != 'moderator':
        abort(403)
    return render_template('moderator.html')


@main.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        abort(403)
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        abort(403)
    # Part C : ORM fetch instead of unsafe SQL
    user = User.query.filter_by(username=session['user']).first()
    if not user:
        abort(403)

    if request.method == 'POST':
        try:
            # Part A: validate string lengths
            current_password = validate_string(request.form.get('current_password'), "Current password", min_len=1, max_len=128)
            new_password = validate_string(request.form.get('new_password'), "New password", min_len=10, max_len=128)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('change_password.html'), 400

        # Part B: verify current password using hashing
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        # Part B: securely update password (hashed)
        # Part C : Using ORM
        user.set_password(new_password)
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')

