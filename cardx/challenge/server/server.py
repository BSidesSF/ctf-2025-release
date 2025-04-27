import random
import enum
from werkzeug.middleware import proxy_fix
from flask import Flask, render_template, request, redirect, flash
from flask_csp.csp import csp_header

# Card related
from random import shuffle
import numpy

# Flask App initialization
app = Flask(__name__)
app.wsgi_app = proxy_fix.ProxyFix(app.wsgi_app)

# CSP headers for the app 
@app.after_request
def apply_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self';" \
        "style-src-elem 'self' fonts.googleapis.com fonts.gstatic.com;" \
        "font-src 'self' fonts.gstatic.com fonts.googleapis.com"
    return response

# Home page - populates the card on the page 
@app.route('/')
@app.route('/home', methods=['GET'])
def home():
    cards = shuffleCards()
    cardsArray = [str(x) for x in cards]
    return render_template('home.html', cards=cardsArray)

# For zoomed in image
@app.route('/image', methods=['GET'])
def image():
    id = request.args.get('id')
    imageSrc = "high-res-" + id + ".webp"
    return render_template('image.html', imageSrc=imageSrc)

# Shuffle Cards
def shuffleCards():
    cards = list(range(1,30))
    shuffle(cards)
    return cards


app.run(host='0.0.0.0', port=8000)
app._static_folder = ''
