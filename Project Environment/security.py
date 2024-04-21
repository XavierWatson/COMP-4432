### Importing flask module for ease of use wep app development
from flask import Flask, render_template, url_for, redirect #Flask page navigation/render modules
from flask_sqlalchemy import SQLAlchemy #sub module for database management to store User objects
from  flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
#setting up the database functionality

bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' #initialize database file
app.config['SECRET_KEY'] = 'secretkey' #creates a key for session cookie
db = SQLAlchemy(app) #initializes database
app.app_context().push() #creates app context fot db creation

login_manager = LoginManager() #initializes login variables and sets context
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) #call method for current user
#databse table for User object
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True) #Unique Identifier Primary key for User Object
    username = db.Column(db.String(20), nullable=False, unique=True) #Username and Password child attributes
    password = db.Column(db.String(80), nullable=False) #nullable serves as attribute validation

#Form for submitting a registration
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self,username):
        existing_user_username= User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "Entered Username Already Exists, Choose A Different Username"
            )
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

#page routes
@app.route('/')
def home(): ##home page
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST']) #GET retrieves form data, and POST submits it
def login(): ##home page
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() #checks if user exists
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data): #validates password
                login_user(user) #logs in stored user object
                return redirect(url_for('dashboard')) #redirects to dashboard
    return render_template('login.html', form=form) #if not re renders login page

@app.route('/dashboard', methods =['GET','POST']) #dashboard route
@login_required #make route require logged in status
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods =['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register(): ##home page
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

with app.app_context(): #uses context to create db tables
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
