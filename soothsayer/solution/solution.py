import numpy
import math
from bs4 import BeautifulSoup
import requests
import sys
import firebase_admin
from firebase_admin import credentials, auth, firestore
import base64
import json
import random


def getIdToken(uid):
       api_key = "AIzaSyAzY2rPDHVd8MzCTRAzsFZySP02C6Hnf3Y"  # Replace with your Firebase project's API key
       url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={api_key}"
       custom_token = getCustomToken(uid)
       custom_token = custom_token.decode('utf-8')
       headers = {"Content-Type": "application/json"}
       data = json.dumps({"token": custom_token, "returnSecureToken": True})
       try:
              response = requests.post(url, headers=headers, data=data)
              response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
              id_token = response.json()["idToken"]
              print(f"Creating Id_token for UID: {uid}")
              return id_token
       except requests.exceptions.RequestException as e:
              print(f"Request failed: {e}")
       except KeyError:
              print("ID token not found in response")
       except json.JSONDecodeError:
              print("Invalid JSON response")

def getCustomToken(uid):
       custom_token = None
       try:
              custom_token = auth.create_custom_token(uid)
              print(f"Creating Custom token for UID: {uid}")
       except Exception as e:
              print(f"Error creating custom token: {e}")
       return custom_token

def createUser():
       anonymous_user = auth.create_user()
       firestore_db = firestore.client()
       seed = random.randint(0,1000)
       guess = []
       data = {"seed":seed, "guess":guess, "score":0}
       firestore_db.collection("users").document(anonymous_user.uid).set(data)
       print(f"Initilize DB entry for UID: {anonymous_user.uid}")
       return anonymous_user

def getSeed(uid):
       firestore_db = firestore.client()
       seed = 0
       user_ref = firestore_db.collection(u'users').document(uid)
       user = user_ref.get()
       if user.exists:
              seed = user.to_dict()['seed']
       else:
              print(u'No such user!')
       print(f'Fetched the seed from DB: {seed}')
       return int(seed)

def addGuess(guesses, uid):
       firestore_db = firestore.client()
       user_ref = firestore_db.collection(u'users').document(uid)
       user_ref.update({"guess": guesses, "score":30})
       print('Updated Guesses in Firestore')

def getFlag(token):
       #token = decodeToken()
       data = {'token':token}
       response = requests.post(url + '/get-flag', data=data)
       text = response.text
       print(f'Flag Response: {response.text}')

def computeGuess(seed):
       numbers = []
       guesses = []
       numpy.random.seed(int(seed))
       for x in range(30):
              state = numpy.random.get_state()
              num = numpy.random.random()
              num = num * 1000
              num = num + 15
              num = math.floor(num)
              numbers.append(num)
              num = num % 2
              guesses.append(num)
              print(f'Round {x+1}: {num}')
       return guesses

if len(sys.argv) == 2:
       url = sys.argv[1]
       cred = credentials.Certificate("../challenge/server/soothsayer-firebase.json")
       firebase_admin.initialize_app(cred)
       user = createUser()
       id_token = getIdToken(user.uid)
       guesses = computeGuess(getSeed(user.uid))
       addGuess(guesses, user.uid)
       getFlag(id_token)
else:
       seed = input("Enter seed:")
       computeGuess(seed)
