from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import pyotp

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///2fa.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    secret_key = db.Column(db.String(16), nullable=False)

    def __init__(self, username, password, secret_key):
        self.username = username
        self.password = password
        self.secret_key = secret_key


# Step 1: Register a user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        secret_key = pyotp.random_base32()

        user = User(username=username, password=password, secret_key=secret_key)
        db.session.add(user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')


# Step 2: User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            session['user_id'] = user.id
            return redirect('/verify')

        return render_template('login.html', message='Invalid credentials')

    return render_template('login.html')


# Step 3: Verify OTP
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    user_id = session.get('user_id')

    if not user_id:
        return redirect('/login')

    user = User.query.get(user_id)

    if request.method == 'POST':
        otp_input = request.form['otp']

        if pyotp.TOTP(user.secret_key).verify(otp_input):
            session['authenticated'] = True
            return redirect('/protected')

        return render_template('verify.html', message='Invalid OTP')

    return render_template('verify.html')


# Protected route
@app.route('/protected')
def protected():
    if not session.get('authenticated'):
        return redirect('/login')

    return "You are logged in!"


if __name__ == '__main__':
    db.create_all()
    app.run()
