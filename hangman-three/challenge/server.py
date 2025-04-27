import random
import enum
from werkzeug.middleware import proxy_fix
from flask import Flask, render_template, url_for
from flask import request, redirect, flash, jsonify, make_response
from flask_csp.csp import csp_header
import string

# Form related
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Regexp, Length
from flask_wtf.csrf import CSRFError


# Login/Registration related
from flask_jwt_extended import create_access_token, current_user, get_jwt_identity
from flask_jwt_extended import jwt_required, JWTManager, set_access_cookies, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash

# Backend
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import attributes
from sqlalchemy import delete
from sqlalchemy.orm import relationship
from sqlalchemy.exc import InterfaceError
import hashlib
import datetime

# Flask App initialization
app = Flask(__name__)
app.wsgi_app = proxy_fix.ProxyFix(app.wsgi_app)


# Setup the Flask-JWT-Extended extension
# CSRF Key 
#https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list#L32C13-L33C1
app.config['SECRET_KEY'] = "tobemodified" 
# JWT Key
app.config["JWT_SECRET_KEY"] = "tobemodified"  
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False 
jwt = JWTManager(app)

# Secret key, also used for CSRF token
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
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    life_lost = db.Column(db.Integer, nullable=False, default=0)
    game_state =  db.Column(db.Enum(StateType), nullable=False,
                      default=StateType.NEW)

    def change_state(self, state):
        self.game_state = state

    def update_life_lost(self, value):
        self.life_lost = value + 1

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Word(id={self.id}, word='{self.word}', letters='{self.letters}', letters_guessed='{self.letters_guessed}', user_id='{self.user_id}')>"
    def update_letters(self, letters):
        self.letters = letters 
    def update_guess(self, letter):
        self.letters_guessed += letter


with app.app_context():
    db.create_all()

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user: User):
    return str(user.id)

# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    try:
        user_id = int(identity) # Convert string identity back to integer for DB query
        return User.query.filter_by(id=user_id).one_or_none()
    except (ValueError, TypeError):
        # Handle cases where identity is not a valid integer string
        return None

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

class GuessForm(FlaskForm):
    letter = HiddenField('Guessed Letter', validators=[DataRequired()])

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
            additional_claims = {"life_lost": str(user.life_lost)}
            access_token = create_access_token(identity=user, additional_claims=additional_claims)
            response = make_response(redirect(url_for('home')))
            set_access_cookies(response, access_token)
            return response
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
@jwt_required()
def home(message=None):
    message = request.args.get('message')
    form = GuessForm()
    msg_arr = ["Starting new game","Game in progress","Congrats you won!","Game over. You lost :("]
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user is None:
        return "Invalid user", 200
    msg = msg_arr[user.game_state.value]
    if message is not None:
         msg = msg + "\n" + message
    if user.game_state != StateType.INPROGRESS:
        if user.game_state == StateType.WON:
            resp = win_response(msg, user, form)
            return resp, 200
        # Lost or new game 
        resp = reset_response(msg, user, form)
        return resp, 200
    wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB is None:
        resp = reset_response(msg, user, form)
        return resp, 200
    # Accounting for edge case where all the characters have been guessed but game isn't set to `WON`
    if  all_letters_guessed(wordDB.letters):
        user.change_state(StateType.WON)
        db.session.commit()
        esp = win_response(msg, user, form)
        return resp, 200
    # In progress game 
    resp = progress_response(msg, wordDB, user, form)
    return resp, 200  
 
# For guess 
@app.route('/guess', methods=['POST'])
@jwt_required()
def guess():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user is None:
        return "Invalid user",200
    # Lost 4 lives, lost the game 
    if user.life_lost >= 4:
        user.change_state(StateType.LOST)
        db.session.commit()
        response = make_response(redirect(url_for('home')))
        return response 
    # Already won the game, no more guesses 
    if user.game_state == StateType.WON:
        response = make_response(redirect(url_for('home')))
        return reponse 
    # Fetch letter from post parameter 
    letter = request.form.get('letter')
    if letter is None:
        return "No guess provided", 200
    letter, error = process_letter(letter)
    if error:
        return letter, 200
    print(f'Fetch for user: {current_user.id}')
    wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB is None:
        return jsonify({'reload': True, 'game':'Invalid'}), 200
    if letter in wordDB.letters_guessed:
        return f"Already guessed {letter}", 200
    wordDB.update_guess(letter)
    db.session.commit()
    # Increment round only when guess is incorrect 
    if letter not in wordDB.word:
        claims = get_jwt()
        life_lost = int(claims["life_lost"])
        user.update_life_lost(int(life_lost))
        db.session.commit()
        print("incorrect guess")
        additional_claims = {"life_lost": str(life_lost +1)}
        new_access_token = create_access_token(identity=current_user, additional_claims=additional_claims)
        response = make_response(redirect(url_for('home', message = f'Letter:{letter} not present')))
        set_access_cookies(response, new_access_token)
        return response
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
    print("correct guess")
    response = make_response(redirect(url_for('home', message = f'Letter:{letter} present')))
    return response


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
@jwt_required()
def reset():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    user.change_state(StateType.NEW)
    db.session.commit()
    word, new_access_token = reset_game(user)
    # Also reset the life_lost in the JWT cookie
    respone = make_response(redirect(url_for('home')))
    set_access_cookies(response, new_access_token)
    return response


# Reset the game - delete word entry in DB, create a new word
def reset_game(user):
    delete_word()
    # Update the player's game state 
    user.start_game()
    db.session.commit()
    # Create a new word for the user
    new_word = create_word(get_random_word())
    db.session.add(new_word)
    db.session.commit()
    # Also reset the life_lost in the JWT cookie
    additional_claims = {"life_lost": str(0)}
    new_access_token = create_access_token(identity=current_user, additional_claims=additional_claims)
    return new_word.word, new_access_token


# Delete words associated with user
def delete_word():
    wordDB = Word.query.filter_by(user_id=current_user.id).one_or_none()
    if wordDB:
        print(f'Delete word by user: {wordDB.word}')
        user_id = current_user.id
        sql = delete(Word).where(user_id == user_id)
        db.session.execute(sql)
        db.session.commit()
    

# Create a random alphanumeric string with length 20
def get_random_word(length=20):
  characters = string.ascii_lowercase + string.digits
  word = ''.join(random.choice(characters) for _ in range(length))
  return word

# Add the new word to the DB 
def create_word(word):
    if not word:
        return None
    print(f'New word generated: {word}')
    letters = [{"letter": letter, "guessed": False} for letter in word]
    word = Word(word=word, user_id=current_user.id, letters=letters, letters_guessed="")
    return word

# Check if all letters have been guessed 
def all_letters_guessed(letters):
  """Checks if all letters in the given list have guessed: True."""
  for letter_dict in letters:
    if not letter_dict["guessed"]:
      return False  # If any letter has guessed: False, return False
  return True


# Response creation 
def progress_response(msg, wordDB, user, form):
    letters_guessed = wordDB.letters_guessed
    stageImg = "hangman-" + str(user.life_lost) + ".png"
    letters = [letter_dict["letter"] if letter_dict["guessed"] else " " for letter_dict in wordDB.letters]
    response = make_response(render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters_guessed = wordDB.letters_guessed, letters=letters,  life_lost = user.life_lost, flag = "", form = form))
    return response
    
def win_response(msg, user, form):
    flag = "CTF{hangm4nW1thW3akJWTK3y}"
    word, new_access_token = reset_game(user)
    letters = [""] * len(word)
    stageImg = "hangman-" + str(user.life_lost) + ".png"
    response = make_response(render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters=letters,  life_lost = user.life_lost, flag = flag, form = form))
     # Also reset the life_lost in the JWT cookie
    set_access_cookies(response, new_access_token)
    return response

def reset_response(msg, user, form):
    word, new_access_token = reset_game(user)
    print(f'Current word: {word}')
    letters = [""] * len(word)
    stageImg = "hangman-" + str(user.life_lost) + ".png"
    response = make_response(render_template('home.html',msg=msg, alphabets=alphabets, stageImg=stageImg, letters=letters,  life_lost = user.life_lost, flag = "", form = form))
    # Also reset the life_lost in the JWT cookie
    set_access_cookies(response, new_access_token)
    return response


@app.route('/logout')
@jwt_required()
def logout():
    resp = make_response(redirect(url_for('login')))
    for cookie in request.cookies:
        resp.delete_cookie(cookie)
    return resp

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error.html', error=e.description), 400

@jwt.unauthorized_loader
def unauthorized_callback(err):
    return redirect('/login')


app.run(host='0.0.0.0', port=8000)
app._static_folder = ''
