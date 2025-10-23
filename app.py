from flask import Flask, render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required

from config import Config
from extensions import db, login_manager, bcrypt, socketio
from models import User
from forms import RegistrationForm, LoginForm
import sockets


def create_app(config_class=Config):
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    socketio.init_app(app) # Initialize SocketIO

    # Import models and create tables
    with app.app_context():
        import models
        db.create_all()

    # Import socket event handlers
    import sockets

    # --- Routes ---
    @app.route("/")
    @app.route("/home")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('chat'))
        return render_template('index.html')

    @app.route("/register", methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('chat'))
        form = RegistrationForm()
        if form.validate_on_submit():
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', title='Register', form=form)

    @app.route("/login", methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('chat'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('chat'))
            else:
                flash('Login Unsuccessful. Please check email and password.', 'danger')
        return render_template('login.html', title='Login', form=form)

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route("/chat")
    @login_required
    def chat():
        # Query all users except the current one to display in the sidebar
        users = User.query.filter(User.id != current_user.id).all()
        return render_template('chat.html', title='Chat', users=users)

    return app

# --- Main Execution ---
app = create_app()

if __name__ == '__main__':
    # Use socketio.run() to start the server with WebSocket support
    socketio.run(app, debug=True, port=5001)