from flask import Flask, render_template, request, redirect, send_from_directory
from flask_csp.csp import csp_header
import requests
import urllib
from werkzeug.middleware import proxy_fix

app = Flask(__name__)
app.wsgi_app = proxy_fix.ProxyFix(app.wsgi_app)

# csp two (Base uri) use cookie ce0443ba6c37f27b65d68287be4cb3f69112d3afb68cff09b144f0048eab253bd9b000f50f8096

@app.after_request
def apply_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self';" \
        "script-src 'self' *.us-central1.run.app;" \
        "connect-src *;" \
        "style-src-elem 'self' fonts.googleapis.com fonts.gstatic.com;" \
        "font-src 'self' fonts.gstatic.com fonts.googleapis.com"
    return response


@app.route('/')
@app.route('/xss-two')
def xssTwo():
    return render_template('xss-two.html')


@app.route('/xss-two-result', methods=['POST', 'GET'])
def xssTwoResult():
    payload = "None"
    if request.method == 'POST':
        payload = request.form['payload']
        r = requests.post('http://127.0.0.1:3000/submit', data={
                          'url': request.base_url + "?payload=" + urllib.parse.quote(payload)})
    if request.method == 'GET' and 'admin' in request.cookies and request.cookies.get("admin") == u"ce0443ba6c37f27b65d68287be4cb3f69112d3afb68cff09b144f0048eab253bd9b000f50f8096":
        payload = request.args.get('payload')
    elif request.method == 'GET':
        app.logger.warning('GET request without valid admin cookie.')
    return render_template('xss-two-result.html', payload=payload)


@app.route('/xss-two-flag', methods=['GET'])
def xssTwoFlag():
    if 'admin' in request.cookies and request.cookies.get("admin") == u"ce0443ba6c37f27b65d68287be4cb3f69112d3afb68cff09b144f0048eab253bd9b000f50f8096":
        return "CTF{Cl0udyFunct10n5F0rA11}"
    else:
        return "Sorry, admins only!"


app.run(host='0.0.0.0', port=8000)
