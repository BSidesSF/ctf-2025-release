Play hangman to guess the flag, the catch is that you have only *4 lives* and you have to guess the *alphanumeric flag*. 

The lives are tracked on the JWT cookie. 
``
 "fresh": false,
  "iat": 1745122377,
  "jti": "4b6e355a-9604-4a87-951a-296a77b148ba",
  "type": "access",
  "sub": "1",
  "nbf": 1745122377,
  "exp": 1745123277,
  "life_lost": "1"
}
``

The JWT is signed with a weak key (`tobemodified`), you can crack it using the wordlist by [Wallarm](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list). This is also the list built into JWT heartbreaker Burp extension.
`hashcat -a 0 -m 16500 <jwt> secrets.list`

To test the level run `python solution.py <CHALLENGE-URL>`