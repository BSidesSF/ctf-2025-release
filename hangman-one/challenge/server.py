import random
import enum
from werkzeug.middleware import proxy_fix
from flask import Flask, render_template, url_for, make_response
from flask import request, redirect, flash, jsonify
from flask_csp.csp import csp_header
import string

# Form related
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Regexp, Length
from flask_wtf.csrf import CSRFError


# Login/Registration related
from flask_login import UserMixin, logout_user, login_user, LoginManager, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Backend
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import attributes
from sqlalchemy import delete
from sqlalchemy.orm import relationship
from sqlalchemy.exc import InterfaceError

# Flask App initialization
app = Flask(__name__)
app.wsgi_app = proxy_fix.ProxyFix(app.wsgi_app)
# Flask_login initialization
login_manager = LoginManager()
login_manager.init_app(app)


# Secret key, also used for CSRF token
app.secret_key = b'ec9de7863408d6fa2a6ed59e725324e0!'
csrf = CSRFProtect(app)

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite"
db = SQLAlchemy(app)
game_word = "hangm4nw1thfr1end5andf03s"

# Game state 
class StateType(enum.Enum):
    NEW = 0
    INPROGRESS = 1
    WON = 2
    LOST = 3 

# User model 
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    life_lost = db.Column(db.Integer, nullable=False, default=0)
    game_state =  db.Column(db.Enum(StateType), nullable=False,
                      default=StateType.NEW)

    def change_state(self, state):
        self.game_state = state

    def start_game(self):
        self.game_state = StateType.INPROGRESS
        self.life_lost = 0

    def increment_life_lost(self):
        self.life_lost = self.life_lost + 1

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return self.username

class Word(db.Model):
    __tablename__ = 'word'
    id = db.Column(db.Integer, primary_key=True)
    word = db.Column(db.String, nullable=False)
    letters = db.Column(db.JSON, nullable=True)
    letters_guessed = db.Column(db.String, nullable=False, default="")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    def __repr__(self):
        return f"<Word(id={self.id}, word='{self.word}', letters='{self.letters}', user_id='{self.user_id}')>"
    def update_letters(self, letters):
        self.letters = letters 
    def update_guess(self, letter):
        self.letters_guessed += letter


with app.app_context():
    db.create_all()

# Forms used by the application
class LoginForm(FlaskForm):
    class Meta:
        csrf = False
    username = StringField('Username', validators=[DataRequired(), Regexp(
        '^\\w+$', message="Username must be AlphaNumeric")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    class Meta:
        csrf = False
    username = StringField('Username', validators=[DataRequired(), Regexp(
        '^\\w+$', message="Username must be AlphaNumeric")])
    # email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('New Password',
                             validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[
                            DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')


# CSP headers for the app 
@app.after_request
def apply_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self';" \
        "style-src-elem 'self' fonts.googleapis.com fonts.gstatic.com;" \
        "font-src 'self' fonts.gstatic.com fonts.googleapis.com"
    return response

# Application routes

# Login
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is None or not user.check_password(form.password.data):
                flash('Invalid username or password', 'error')
                return redirect('/login')
            login_user(user)
            return redirect('/home')
    return render_template('login.html', form=form)

# Registration
@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering')
        return redirect('/login')
    return render_template('register.html', form=form)


# Hangman landing page
@app.route('/home', methods=['GET'])
@login_required
def home():
    # Initial values 
    msg_arr = ["Starting new game","Game in progress","Congrats you won!","Game over. You lost :("]
    # Populate the alphanumeric button grid 
    alphabets = list(string.ascii_lowercase + string.digits)
    # Get the current user's game state
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user is None:
        return "Invalid user", 200
    # Set the message to display based on game state 
    msg = msg_arr[user.game_state.value]
    # If this is the first time the user is logging in 
    if user.game_state == StateType.NEW:
        if not start_game():
            return "Game state is invalid.", 200
    life_lost = user.life_lost
    wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    # Shouldn't run into this state, but just in case 
    if wordDB is None:
        return "Game state is invalid.", 200
    word = wordDB.word
    letters_guessed = wordDB.letters_guessed
    letters = [letter_dict["letter"] if letter_dict["guessed"] else " " for letter_dict in wordDB.letters]   
    stageImg = "hangman-" + str(life_lost) + ".png"
    return render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters=letters, letters_guessed = letters_guessed, life_lost = life_lost)

# For guess 
@app.route('/guess', methods=['GET'])
@login_required
def guess():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user is None:
        return "Invalid user",200
    # Lost all 4 lives, Game over. 
    if user.life_lost >= 4:
        user.change_state(StateType.LOST)
        db.session.commit()
        return jsonify({'reload': True, 'game':'lost'}), 200
    # Already won the game 
    if user.game_state == StateType.WON:
        return jsonify({'reload': True, 'game':'won'}), 200
    letter = request.args.get('letter')
    # No `letter` argument in the request
    if letter is None:
        return "No guess provided", 200
    letter, error = process_letter(letter)
    if error:
        return letter, 200 
    wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB is None:
        return jsonify({'reload': True, 'game':'invalid'}), 200
    # If the letter has been guessed already 
    if letter in wordDB.letters_guessed:
        return f"Already guessed {letter}", 200
    wordDB.update_guess(letter)
    db.session.commit()
    # Increment life_lost when guess is incorrect 
    if letter not in wordDB.word:
        user.increment_life_lost()
        db.session.commit()
        data = {"letter": letter, "present": "false", "life_lost":user.life_lost}
        return jsonify(data), 200
    if letter in wordDB.word:
        positions = []
        new_letters = []
        for index, letter_dict in enumerate(wordDB.letters):
            if letter_dict["letter"] == letter:
                letter_dict["guessed"] = True
                positions.append(index + 1)
            new_letters.append(letter_dict)
        wordDB.letters = new_letters
        # need to set this attribute to let DB know the JSON attribute has changed 
        attributes.flag_modified(wordDB, "letters")
        db.session.commit()
    if  all_letters_guessed(wordDB.letters):
        user.change_state(StateType.WON)
        db.session.commit()
        return jsonify({'reload': True, 'game':'won'}), 200 
    data = {"letter": letter, "present": "true", "positions":positions, "life_lost":user.life_lost}
    return jsonify(data), 200
        
        
def process_letter(letter):
    if len(letter) != 1:
        return "Invalid guess, only single AlphaNumeric characters allowed", True 
    if 'a' <= letter <= 'z' or 'A' <= letter <= 'Z':
        return letter.lower(), False
    elif '0' <= letter <= '9':
        return letter, False 
    else:
        return "Invalid guess, only single AlphaNumeric characters allowed", True

# Start the game
def start_game():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    user.start_game()
    db.session.commit()
    word = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if word is None:
        new_word = create_word(game_word)
        db.session.add(new_word)
        db.session.commit()
        return new_word.word
    return None

# Add the word to the DB 
def create_word(word):
    if not word:
        return None
    letters = [{"letter": letter, "guessed": False} for letter in word]
    word = Word(word=word, user_id=current_user.id, letters=letters, letters_guessed="")
    return word

# Check if all letters have been guessed 
def all_letters_guessed(letters):
  for letter_dict in letters:
    if not letter_dict["guessed"]:
      return False
  return True

# Helper functions
@login_manager.user_loader
def load_user(id):
    return db.session.get(User, id)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error.html', error=e.description), 400

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

@app.route('/logout')
@login_required
def logout():
    resp = make_response(redirect(url_for('login')))
    for cookie in request.cookies:
        resp.delete_cookie(cookie)
    return resp


app.run(host='0.0.0.0', port=8000)
app._static_folder = ''
