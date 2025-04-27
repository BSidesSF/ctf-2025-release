import random
import enum
from werkzeug.middleware import proxy_fix
from flask import Flask, render_template, url_for
from flask import request, redirect, flash, jsonify, make_response
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
import hashlib
import datetime
import sqlite3


# Flask App initialization
app = Flask(__name__)
app.wsgi_app = proxy_fix.ProxyFix(app.wsgi_app)
# Flask_login initialization
login_manager = LoginManager()
login_manager.init_app(app)

print(f'sqlite threadsafety: {sqlite3.threadsafety}')

# Secret key, also used for CSRF token
app.secret_key = b'18259517ebeb3a4ed5fbd135fe966ad4!'
csrf = CSRFProtect(app)

# Alphanumeric button grid
alphabets = list(string.ascii_lowercase + string.digits)

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite"
db = SQLAlchemy(app)

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

    def increment_life_lost(self):
        self.life_lost = self.life_lost + 1

    def start_game(self):
        self.game_state = StateType.INPROGRESS
        self.life_lost = 0

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
    cookie_string = db.Column(db.String(50), nullable=False, default="Null", unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

    def __repr__(self):
        return f"<Word(id={self.id}, word='{self.word}', letters='{self.letters}', letters_guessed='{self.letters_guessed}', cookie_string='{self.cookie_string}', user_id='{self.user_id}')>"
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
    msg_arr = ["Starting new game","Game in progress","Congrats you won!","Game over. You lost :("]
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user is None:
        return "Invalid user", 200
    msg = msg_arr[user.game_state.value]
    cookie_string = request.cookies.get('state')
    if user.game_state != StateType.INPROGRESS:
        if user.game_state == StateType.WON:
            resp = win_response(msg, cookie_string, user)
            return resp, 200
        # Lost or new game 
        resp = reset_response(msg, cookie_string, user)
        return resp, 200
    # If `state` cookie is set, give it preference to fetch word
    if cookie_string:
        print(f'Fetching for cookie string: {cookie_string}')
        wordDB = Word.query.filter_by(cookie_string=cookie_string).one_or_none()
        if not wordDB:
            print(f'Have cookie string {cookie_string} but no cookie found')
    else:
        wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB is None:
        resp = reset_response(msg, cookie_string, user)
        return resp, 200
    # Accounting for edge case where all the characters have been guessed but game isn't set to `WON`
    if  all_letters_guessed(wordDB.letters):
        user.change_state(StateType.WON)
        db.session.commit()
        esp = win_response(msg, cookie_string, user)
        return resp, 200
    # In progress game 
    resp = progress_response(msg, wordDB, user)
    return resp, 200  
 
# For guess 
@app.route('/guess', methods=['GET'])
@login_required
def guess():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user is None:
        return "Invalid user",200
    # Lost 4 lives, lost the game 
    if user.life_lost >= 4:
        print(f'Lost 4+ lives, state lost for {current_user.id}')
        user.change_state(StateType.LOST)
        db.session.commit()
        return jsonify({'reload': True, 'game':'Lost'}), 200
    # Already won the game, no more guesses 
    if user.game_state == StateType.WON:
        return jsonify({'reload': True, 'game':'Won'}), 200
    # Fetch letter from get parameter 
    letter = request.args.get('letter')
    if letter is None:
        return "No guess provided", 200
    letter, error = process_letter(letter)
    if error:
        return letter, 200
    # If `state` cookie is set, give it preference to fetch word
    cookie_string = request.cookies.get('state')
    if cookie_string:
        print(f'Guess with cookie {cookie_string}')
        wordDB = Word.query.filter_by(cookie_string=cookie_string).one_or_none()
        if not wordDB:
            print(f'Have cookie string {cookie_string} but no cookie found')
    else:
        print(f'Fetch for user: {current_user.id}')
        wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB is None:
        print(f"Invalid state for {current_user.id}, cs: {cookie_string}")
        return jsonify({'reload': True, 'game':'Invalid'}), 400
    if letter in wordDB.letters_guessed:
        return f"Already guessed {letter}", 200
    wordDB.update_guess(letter)
    db.session.commit()
    # Increment round only when guess is incorrect 
    if letter not in wordDB.word:
        user.increment_life_lost()
        db.session.commit()
        data = {"letter": letter, "present": "false", "life_lost":user.life_lost}
        return jsonify(data), 200
    # Update word state when guess is correct
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


# Make sure letter is alphanumeric
def process_letter(letter):
    if len(letter) != 1:
        return "Invalid guess, only single AlphaNumeric characters allowed", True 
    if 'a' <= letter <= 'z' or 'A' <= letter <= 'Z':
        return letter.lower(), False
    elif '0' <= letter <= '9':
        return letter, False 
    else:
        return "Invalid guess, only single AlphaNumeric characters allowed", True

# To reset the game forcibly  
@app.route('/reset', methods=['GET'])
@login_required
def reset():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    cookie_string = request.cookies.get('state')
    user.change_state(StateType.NEW)
    db.session.commit()
    word, cookie_string = reset_game(user, cookie_string)
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('state', cookie_string, httponly=True)
    return resp


# Reset the game - delete word entry in DB, create a new word
def reset_game(user, cookie_string=None):
    delete_word(cookie_string)
    # Update the player's game state 
    user.start_game()
    db.session.commit()
    # Create a new word for the user
    new_word = create_word(get_random_word())
    db.session.add(new_word)
    db.session.commit()
    return new_word.word, new_word.cookie_string


# Delete words associated with cookie_string and the user
def delete_word(cookie_string=None):
    if cookie_string:
        wordDB = Word.query.filter_by(cookie_string=cookie_string).first()
        if wordDB:
            print(f'Delete word by cookie string (user {current_user.id}): {wordDB.word}, cs: {cookie_string}')
            sql = delete(Word).where(Word.cookie_string == cookie_string)
            rp = db.session.execute(sql)
            print(f'Deleted {rp.rowcount} rows')
            db.session.commit()
    wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB:
        print(f'Delete word by user (user {current_user.id}): {wordDB.word}, {wordDB.cookie_string}')
        user_id = current_user.id
        sql = delete(Word).where(Word.user_id == user_id)
        rp = db.session.execute(sql)
        print(f'Deleted {rp.rowcount} rows')
        db.session.commit()


# Create a random alphanumeric string with length 25
def get_random_word(length=25):
  characters = string.ascii_lowercase + string.digits
  word = ''.join(random.choice(characters) for _ in range(length))
  return word

# Add the new word to the DB 
def create_word(word):
    if not word:
        return None
    letters = [{"letter": letter, "guessed": False} for letter in word]
    cookie_string = get_cookie_string(word)
    print(f'New word generated for {current_user.id}: {word}, cs: {cookie_string}')
    word = Word(word=word, user_id=current_user.id, letters=letters, letters_guessed="", cookie_string=cookie_string)
    return word

# Check if all letters have been guessed 
def all_letters_guessed(letters):
  """Checks if all letters in the given list have guessed: True."""
  for letter_dict in letters:
    if not letter_dict["guessed"]:
      return False  # If any letter has guessed: False, return False
  return True

# Create a cookie that is a md5 of the word + suffix
def get_cookie_string(input_string):
    now = datetime.datetime.now().isoformat()  # Get current datetime in ISO format
    combined_string = input_string + "1nn13" + now
    encoded_string = combined_string.encode('utf-8')  # Important: Encode to bytes
    md5_hash = hashlib.md5(encoded_string).hexdigest()
    return md5_hash

# Response creation 
def progress_response(msg, wordDB, user):
    letters_guessed = wordDB.letters_guessed
    stageImg = "hangman-" + str(user.life_lost) + ".png"
    letters = [letter_dict["letter"] if letter_dict["guessed"] else " " for letter_dict in wordDB.letters]
    resp = make_response(render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters_guessed = wordDB.letters_guessed, letters=letters,  life_lost = user.life_lost, flag = ""))
    return resp
    
def win_response(msg, cookie_string, user):
    flag = "CTF{h4ngmanr0ulett3w1n}"
    word, cookie_string = reset_game(user, cookie_string)
    letters = [""] * len(word)
    stageImg = "hangman-" + str(user.life_lost) + ".png"
    resp = make_response(render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters=letters,  life_lost = user.life_lost, flag = flag))
    resp.set_cookie('state', cookie_string, httponly=True) #sets flags
    return resp

def reset_response(msg, cookie_string, user):
    word, cookie_string = reset_game(user, cookie_string)
    print(f'Reset, new word for {current_user.id}: {word}')
    letters = [""] * len(word)
    stageImg = "hangman-" + str(user.life_lost) + ".png"
    resp = make_response(render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters=letters,  life_lost = user.life_lost, flag = ""))
    resp.set_cookie('state', cookie_string, httponly=True) #sets flags
    return resp

# Helper functions
@login_manager.user_loader
def load_user(id):
    return db.session.get(User, id)


@app.route('/logout')
@login_required
def logout():
    resp = make_response(redirect(url_for('login')))
    for cookie in request.cookies:
        resp.delete_cookie(cookie)
    return resp

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error.html', error=e.description), 400

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')


app.run(host='0.0.0.0', port=8000)
app._static_folder = ''
