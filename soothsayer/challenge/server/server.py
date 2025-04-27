from flask import Flask, request
import requests
from werkzeug.middleware import proxy_fix
import firebase_admin
from firebase_admin import credentials, auth, firestore
import numpy
import math


app = Flask(__name__)
app.wsgi_app = proxy_fix.ProxyFix(app.wsgi_app)

# Application Routes
## Home 
@app.route('/', methods=['GET','POST'])
@app.route('/get-flag', methods=['GET','POST'])
def getFlag():
    # To handle load balancer 
    if request.method == 'GET':
        return "Server is up, challenge requires post", 200
    flag = "CTF{S33dth3tw1st3r}"
    # Post request
    id_token = request.form.get('token')
    if id_token:
        decoded_token = auth.verify_id_token(id_token)
        # Get the user id by decoding the token
        uid = decoded_token['uid']
        # Fetch all guesses made by the user
        guess, seed = fetchGuesses(uid)
        if len(guess) >= 30:
            state = validateGuesses(guess, seed)
            if state == True:
                return flag
            else:
                return "Incorrect guesses made, please restart app"
        else:
            return "Need to make atleast 30 guesses before fetching the flag."
    else:
        return "Missing Access token, forbidden", 403


# Helper functions
## Fetch guesses from Firestore
def fetchGuesses(uid):
    firestore_db = firestore.client()
    guess = []
    seed = 0
    user_ref = firestore_db.collection(u'users').document(uid)
    user = user_ref.get()
    if user.exists:
        guess = user.to_dict()['guess']
        seed = user.to_dict()['seed']
    else:
        print(u'No such user!')
    print("Guesses:", guess, ",Seed:", int(seed))
    return guess, int(seed) 

    

## Validate guesses
def validateGuesses(guesses, seed):
    numpy.random.seed(int(seed))
    for guess in guesses:
        state = numpy.random.get_state()
        num = numpy.random.random()
        num = num * 1000
        num = num + 15
        num = math.trunc(num)
        num = num % 2
        if guess != num:
            return False
    return True


# Todo - update to production Firebase service account 
cred = credentials.Certificate("soothsayer-firebase.json")
firebase_admin.initialize_app(cred)
app.run(host='0.0.0.0', port=8000)