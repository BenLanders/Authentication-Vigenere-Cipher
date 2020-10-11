import random
import string
import hashlib

def upperCase(message):
    return message.upper()

def generateKey(message, key): 
    key = list(key) 
    if len(message) == len(key): 
        return(key) 
    else: 
        for i in range(len(message) - 
                       len(key)): 
            key.append(key[i % len(key)]) 
    return("" . join(key))

def encryptText(string, key): 
    cipher_text = [] 
    for i in range(len(string)):
        if string[i] == ' ':
            x = (ord(' '))
        else:
            x = (ord(string[i]) + 
                ord(key[i])) % 26
            x += ord('A')
        cipher_text.append(chr(x)) 
    return("" . join(cipher_text))
    
       
def decryptText(cipher_text, key): 
    orig_text = [] 
    for i in range(len(cipher_text)):
        if cipher_text[i] == ' ':
            x = (ord(' '))
        else:
            x = (ord(cipher_text[i]) - 
                ord(key[i]) + 26) % 26
            x += ord('A')
        orig_text.append(chr(x)) 
    return("" . join(orig_text))

def crypto():
    crypto_menu = input('\nWould you like to encrypt (e) or decrypt (d) a message or quit(q)?')
    if crypto_menu == 'e':
        start_encrypt()
    elif crypto_menu == 'd':
        start_decrypt()
    else: stop()
 
def start_encrypt():
    f = open ('secretmessage.txt', 'w')
    message = upperCase(input('Enter a message:'))
    keyword = loginPassword
    key = generateKey(message, keyword) 
    cipher_text = encryptText(message,key) 
    print("Encrypted text:", cipher_text)
    f.write(cipher_text)
    f.close()
    crypto()

def start_decrypt():
    f = open('secretmessage.txt', 'r')
    cipher_text = (f.readline())
    f.close()
    keyword = loginPassword
    key = generateKey(cipher_text, keyword)  
    print("Decrypted text:",  
           decryptText(cipher_text, key))
    crypto()

def stop():
    exit()

def register():
    while True:
        username = input('\nEnter a username:')
        one = input('\nEnter a password:')
        two = input('\nRetype your password:')

        if one == two:
            break
        else:
            print('\nPasswords are not the same. Try again...\n')

    f = open ('userdata.txt', 'w')
    s = open ('salt.txt', 'w')
    letters = string.ascii_letters
    salt = str( ''.join(random.choice(letters) for i in range(3)))
    passwordSalt = one+salt
    h = hashlib.md5(passwordSalt.encode())
    f.write(username + '\n' + h.hexdigest())
    s.write(salt)
    f.close()
    s.close()
    login()

def login():
    f = open("userdata.txt", "r")
    s = open('salt.txt', 'r')

    user =(f.readline())
    password =(f.readline())
    salt =(s.readline())
    f.close()
    s.close()

    while True:
        global loginPassword
        loginUsername = input('\nEnter your username:')
        loginPassword = input('\nEnter your password:')
        passwordSalt = loginPassword + salt
        h2 = hashlib.md5(passwordSalt.encode())
        loginHash = h2.hexdigest()

        if password == loginHash and user == loginUsername + '\n':
            print('\nWelcome ' + loginUsername + '!')
            break       
        else:
            print('Your username and/or password are incorrect.')
    crypto()

loginPassword = ''
menu = input ('Do you want to register (r) as a new user or login (l) as an existing user?')
if menu == 'r':
    register()
if menu == 'l':
    login()



