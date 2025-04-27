Play hangman to guess a random 25 character alphanumeric string. 

* Every user starts with a random word, the word sticks until the user wins/loses the game. Or resets it. 
* Lives are tied to the user and there is a cookie called the `state` that can be used to fetch the same word.
* So if you were to create a new user, guess 3 characters, you don't run the risk of reseting the word due to a loss. 
* Everytime you make a guess, also fetch the home page to see if the flag was returned, to avoid resetting due to a win.

To test the challenge, run `python3 solution.py http://127.0.0.1:8000`.