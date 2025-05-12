import streamlit as st 
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# data information for user
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.page = "Home"
    st.session_state.failed_attempts = 0
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)
        
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key[:32])

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# Main app
st.title("Secure Data Storage")

# Navigation
if st.session_state.authenticated:
    menu = ["Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Home", "Register", "Login"]

choice = st.sidebar.selectbox("Menu", menu)

# Handle page selection
if choice == "Logout":
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.page = "Home"
    choice = "Home"

# Page content
if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption App")
    st.write("This app allows you to securely store and retrieve data using encryption.")

elif choice == "Register":
    st.subheader("Create a new account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists.")
            else:
                hashed_password = hash_password(password)
                stored_data[username] = {
                    "password": hashed_password, 
                    "data": []
                }
                save_data(stored_data)
                st.success("Account created successfully. Please login.")
        else:
            st.error("Please enter both username and password.")
            
elif choice == "Login":
    st.subheader("Login to your account")
    
    if time.time() < st.session_state.lockout_time:
       remaining_time = int(st.session_state.lockout_time - time.time())
       st.error(f"Too many failed attempts. Please try again in {remaining_time} seconds.")
       st.stop()
       
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username and password:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.failed_attempts = 0
                st.session_state.page = "Store Data"
                st.success(f"Login successful. Welcome, {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining_attempts = 3 - st.session_state.failed_attempts
                st.error(f"Invalid username or password. {remaining_attempts} attempts left.")
                
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("Too many failed attempts. You are locked out for 60 seconds.")
        else:
            st.error("Please enter both username and password")

elif choice == "Store Data":
    if not st.session_state.authenticated:
        st.warning("Please login to store data.")
    else:
        st.subheader("Store Encrypted Data")
        st.write(f"Welcome, {st.session_state.username}!")
        
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter passkey for encryption", type="password")
        
        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.username]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("Data encrypted and stored successfully!")
            else:
                st.error("Please enter both data and passkey.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated:
        st.warning("Please login to retrieve data.")
    else:
        st.subheader("Retrieve Your Data")
        st.write(f"Welcome back, {st.session_state.username}!")
        
        passkey = st.text_input("Enter your passkey to decrypt all data", type="password")
        
        if st.button("Decrypt All Data"):
            if passkey:
                user_data = stored_data.get(st.session_state.username, {}).get("data", [])
                
                if not user_data:
                    st.info("No encrypted data found for your account.")
                else:
                    st.subheader("Your Decrypted Data:")
                    for i, encrypted_item in enumerate(user_data, 1):
                        decrypted_data = decrypt_text(encrypted_item, passkey)
                        if decrypted_data:
                            st.text_area(f"Data Item {i}", value=decrypted_data, height=100, key=f"data_{i}")
                        else:
                            st.error(f"Failed to decrypt item {i}. Wrong passkey?")
            else:
                st.error("Please enter your passkey")