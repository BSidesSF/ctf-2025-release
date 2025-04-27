import requests
import sys
import random
from bs4 import BeautifulSoup
import string
import hashlib


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

def guess(session, url, letter):
    response = session.get(url + '/guess?&letter=' + letter)
    print(f'Guessing: {letter}, Status Code: {response.status_code}, Response: {response.text}')

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

def get_flag(html_response):
    flag = ""
    soup = BeautifulSoup(html_response, 'html.parser')
    div_ctf = soup.find_all('div', class_='ctf')
    if not div_ctf:
        print(RED + f'Divs with class `ctf` not found.' + ENDC)
        exit()
    result = ""
    for div in div_ctf:
        result += div.text.strip()
    part1 = ''.join(result[:-1]) #join all characters except the last one
    part2 = result[-1] #get the last character
    # Find all the letters on the page
    div_letters = soup.find_all('div', class_='letter')
    # Process or print the div tags
    if not div_letters:
        print(RED + f'Divs with class `letter` not found.`' + ENDC)
        exit()
    letters = ""
    for div in div_letters:
        # Access attributes or text content of each div
        letters += div.attrs['data-value']
    return part1 + letters + part2
            

def main():
    if len(sys.argv) != 2:
        print('Please specify challenge URL')
        print('python3 solution.py <challenge-url>')
        print('E.g, python3 solution.py http://127.0.0.1:8000')
        exit()
    url = sys.argv[1]
    flag = 'hangm4nw1thfr1end5andf03s'
    # Set-up your main user
    with requests.Session() as session:
        while True:
            response, username, password = register(session, url)
            if check_error(response, session):
                print(GREEN + f'Successfully registered user: {username}' + ENDC)
                break  # Exit the loop on success
            else:
             print(RED + f'Retrying registration' + ENDC)
        response = login(session, url, username, password)
        response = home(session, url)
        # Test an incorrect guess 
        print(RED + f'Attempting incorrect guess: z' + ENDC)
        response = guess(session, url, "z")
        # Process the response as needed (e.g., check for success, extract data)
    	# Guess each letter in the flag 
        print(GREEN + f'Attempting correct flag guesses' + ENDC)
        for letter in flag:
            response = guess(session, url, letter)
        print(f'Fetching home page and parsing result for flag.')
        response = home(session, url)
        flag = get_flag(response.text)
        print(GREEN + f'Flag is {flag}' + ENDC)

if __name__ == "__main__":
    main()