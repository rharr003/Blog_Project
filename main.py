import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL_FIX'), 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

class LogIn(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired()])
    password = StringField("password", validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        hashed_pass = werkzeug.security.generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=8)
        user = User.query.filter_by(email=data['email']).first()
        if user:
            flash("There is already an account under that email address. Please log in.")
            return render_template("register.html")
        else:
            new_user = User(email=data['email'],
                            password=hashed_pass,
                            name=data['name'])
            db.session.add(new_user)
            db.session.commit()
            return render_template('secrets.html', user=new_user)
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        data = request.form
        user = User.query.filter_by(email=data['email']).first()
        try:
            if check_password_hash(user.password, data['password']):
                login_user(user)
                return redirect(url_for('secrets'))
        except AttributeError:
            flash("Invalid login, please try again.")
            return render_template("login.html")
        else:
            flash("Invalid login, please try again.")
            return render_template("login.html")

    else:
        return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():

    return render_template("secrets.html", user=current_user, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")

if __name__ == "__main__":
    app.run(debug=True)
