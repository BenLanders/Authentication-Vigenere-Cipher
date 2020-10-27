import tkinter as tk
import string
import random
import hashlib

def clear():
    tk.Label(app, text="                                                                                                                                ").grid(row=0,sticky=tk.S)

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
        if not string[i].isalpha():
            x = (ord(string[i]))
        elif string[i] == ' ':
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
        if not cipher_text[i].isalpha():
            x = (ord(cipher_text[i]))
        elif cipher_text[i] == ' ':
            x = (ord(' '))
        else:
            x = (ord(cipher_text[i]) - 
                ord(key[i]) + 26) % 26
            x += ord('A')
        orig_text.append(chr(x)) 
    return("" . join(orig_text))

def start_encrypt():
    tk.Label(window,text='                                                                                                                                                                   ').grid(row=4,columnspan=2,sticky=tk.W)
    f = open ('secretmessage.txt', 'w')
    originalMessage = (e6.get("1.0",'end-1c'))
    message = upperCase(originalMessage)
    keyword = loginPassword
    key = generateKey(message, keyword) 
    cipher_text = encryptText(message,key) 
    print("Encrypted text:", cipher_text)
    tk.Label(window,text="Encrypted text: " + cipher_text,font=11).grid(row=4,columnspan=2,padx=10,pady=10,sticky=tk.W)
    f.write(cipher_text)
    f.close()

def start_decrypt():
    tk.Label(window,text='                                                                                                                                                                   ').grid(row=4,columnspan=2,sticky=tk.W)
    f = open('secretmessage.txt', 'r')
    cipher_text = (f.read())
    f.close()
    keyword = loginPassword
    key = generateKey(cipher_text, keyword)
    print("Decrypted text:",  
           decryptText(cipher_text, key))
    decrypt = decryptText(cipher_text, key)
    tk.Label(window,text="Decrypted text: " + decrypt,font=11).grid(row=4,columnspan=2,padx=10,pady=10,sticky=tk.W)

def register():   
    username = (e1.get())
    one = (e2.get())
    two = (e3.get())

    if one == two:
        tk.Label(app, text="                                                                                                                    ").grid(row=0,sticky=tk.S)
        tk.Label(app, text="Registration Success", fg="green", font=("calibri", 11)).grid(row=0,sticky=tk.S)
        print('Welcome ' + username)
    else:
        tk.Label(app, text="                                                                                                                    ").grid(row=0,sticky=tk.S)
        e1.delete(0, 'end')
        e2.delete(0, 'end')
        e3.delete(0, 'end')
        tk.Label(app, text="Passwords are not the same. Try again...", fg="red", font=("calibri", 11)).grid(row=0,sticky=tk.S)
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

def instructions():
    global window
    window = tk.Toplevel(app)
    window.title('Encrypt or Decrypt')
    window.geometry('530x500')
    tk.Label(window, text="Encrypt or Decrypt", font=LARGE_FONT).grid(row=0,column=0,columnspan=2,pady=5,padx=10)
    tk.Label(window, text=
"""Use the form below to encrypt a message. The encrypted
message is saved to the file 'secretmessage.txt'. The
encrypted message can then be decrypted.""",font=REGULAR_FONT).grid(row=1,column=0,columnspan=2,pady=5,padx=10,sticky=tk.E)
    global e6
    e6 = tk.Text(window,fg='black',bg='yellow', height=5,width=46,font=1)
    e6.grid(row=2, column=0, columnspan=2, padx=10)
    button = tk.Button(window, text="Encrypt to File",fg='yellow',bg='red',activebackground = 'red',font=1,width=15,
                            command=start_encrypt)
    button.grid(row=3,column=0,padx=10,pady=10,sticky=tk.W)

    button2 = tk.Button(window, text="Decrypt from File",fg='yellow',bg='red',activebackground='red',font=1,width=15,
                            command=start_decrypt)
    button2.grid(row=3,column=1,padx=10,pady=10,sticky=tk.E)
    

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
        loginUsername = (e4.get())
        loginPassword = (e5.get())
        passwordSalt = loginPassword + salt
        h2 = hashlib.md5(passwordSalt.encode())
        loginHash = h2.hexdigest()

        if password == loginHash and user == loginUsername + '\n':
            print('\nWelcome ' + loginUsername + '!')
            tk.Label(app, text="                                                                                                                    ").grid(row=0,sticky=tk.S)
            loginLabel=tk.Label(app, text="Login Success", fg="green", font=("calibri", 11))
            loginLabel.grid(row=0,sticky=tk.S)
            app.withdraw()
            instructions()
            break       
        else:
            print('Your username and/or password are incorrect.')
            e4.delete(0, 'end')
            e5.delete(0, 'end')
            tk.Label(app, text="                                                                                                                    ").grid(row=0,sticky=tk.S)
            loginLabel=tk.Label(app, text="Your username and/or password are incorrect. Try again...", fg="red", font=("calibri", 11))
            loginLabel.grid(row=0,sticky=tk.S)
            break

LARGE_FONT= ('Verdana', 14, 'bold')
REGULAR_FONT= ('Verdana', 12)


class Vigenere(tk.Tk):

    def __init__(self, *args, **kwargs):
        
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)

        container.grid()

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (StartPage, RegisterPage, LoginPage):

            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

        
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        label = tk.Label(self, text="Vigenere Cipher Tool", font=LARGE_FONT)
        label.grid(row=0,column=1,pady=5,padx=10)
        #img = tk.PhotoImage(file="J:\crack\lock.png")
        #L1=tk.Label(self, image=img)
        #L1.photo=img
        #L1.grid(row=2,column=1,sticky=tk.N)
        label = tk.Label(self, text=
"""This program uses the Vigenere cipher to encrypt or decrypt
text. The encrypted text is saved in the file
'secretmessage.txt'. The secret key is the user's password.""",font=REGULAR_FONT)
        label.grid(row=1,column=0,columnspan=3,pady=20,padx=10,sticky=tk.E)

        button = tk.Button(self, text="Register",fg='yellow',bg='red',activebackground ='red',font=1,width=10,
                            command=lambda: controller.show_frame(RegisterPage))
        button.grid(row=2,column=0,padx=10,pady=45)

        button2 = tk.Button(self, text="Login",fg='yellow',bg='red',activebackground='red',font=1,width=10,
                            command=lambda: controller.show_frame(LoginPage))
        button2.grid(row=2,column=2,pady=45)


class RegisterPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self,text="Register", font=LARGE_FONT)
        label.grid(row=0,column=0,columnspan=3,pady=10,padx=10)
        label = tk.Label(self, foreground='black',text="Username:", font=REGULAR_FONT)
        label.grid(row=1,column=0,pady=10,padx=10,sticky=tk.W)
        label = tk.Label(self, foreground='black',text="Password:", font=REGULAR_FONT)
        label.grid(row=2,column=0,pady=10,padx=10,sticky=tk.W)
        label = tk.Label(self, foreground='black',text="Re-type password:", font=REGULAR_FONT)
        label.grid(row=3,column=0,pady=10,padx=10,sticky=tk.W)

        button1 = tk.Button(self, text="Back to Home",fg='yellow',bg='red',activebackground='red',font=1,width=14,
                            command=lambda: [controller.show_frame(StartPage),clear()])
        button1.grid(row=4,column=0,pady=20)

        button2 = tk.Button(self, text="Register Account",fg='yellow',bg='red',activebackground='red',font=1,width=14,
                            command=lambda: [clear(),register()])
        button2.grid(row=4,column=1)

        button3 = tk.Button(self, text="Login",fg='yellow',bg='red',activebackground='red',font=1,width=14,
                            command=lambda: [controller.show_frame(LoginPage),clear()])
        button3.grid(row=4,column=2)

        global e1
        global e2
        global e3

        e1 = tk.Entry(self,fg='black',bg='yellow',width=30,font=1)
        e2 = tk.Entry(self,fg='black',bg='yellow',width=30,font=1)
        e3 = tk.Entry(self,fg='black',bg='yellow',width=30,font=1)

        e1.grid(row=1, column=1, columnspan=2)
        e2.grid(row=2, column=1, columnspan=2)
        e3.grid(row=3, column=1, columnspan=2)



class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Login", font=LARGE_FONT)
        label.grid(row=0,column=1,pady=10,padx=10)

        label = tk.Label(self, foreground='black',text="Username", font=LARGE_FONT)
        label.grid(row=1,column=0,pady=10,padx=10,sticky=tk.W)

        label = tk.Label(self, foreground='black',text="Password", font=LARGE_FONT)
        label.grid(row=2,column=0,pady=10,padx=10,sticky=tk.W)

        button1 = tk.Button(self, text="Back to Home",fg='yellow',bg='red',activebackground = 'red',font=1,width=14,
                            command=lambda: [controller.show_frame(StartPage),clear()])
        button1.grid(row=3,column=0,padx=10,pady=45)


        button2 = tk.Button(self, text="Login",fg='yellow',bg='red',activebackground='red',font=1,width=14,
                            command=login)
        button2.grid(row=3,column=2,pady=45,sticky=tk.E)
        
        global e4
        global e5

        e4 = tk.Entry(self,fg='black',bg='yellow',width=30,font=1)
        e5 = tk.Entry(self,fg='black',bg='yellow',width=30,font=1)

        e4.grid(row=1, column=1, columnspan=2)
        e5.grid(row=2, column=1, columnspan=2)
      
app = Vigenere()
app.geometry('530x300')
app.mainloop()
