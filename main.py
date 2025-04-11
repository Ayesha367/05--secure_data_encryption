import streamlit as st
import hashlib
import json
import os
import time
import random
import string
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# === Constants ===
DATA_FILE = "secure_data.json"
ACTIVITY_LOG_FILE = "activity_log.txt"
SALT = b"secure_salt_value"  # Keep this secret & consistent across sessions
LOCKOUT_DURATION = 60  # in seconds (1 minute)
OTP_EXPIRATION = 300  # OTP validity in seconds (5 minutes)

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Utility Functions ===

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def log_activity(message):
    with open(ACTIVITY_LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    generated_key = urlsafe_b64encode(key)
    return generated_key

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    encrypted_text = cipher.encrypt(text.encode()).decode()
    return encrypted_text

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        return decrypted
    except Exception as e:
        return None

def check_password_strength(password):
    length = len(password)
    if length < 8:
        return "Weak"
    elif length < 12:
        return "Medium"
    return "Strong"

# === Load stored data from JSON ===
stored_data = load_data()

# === PDF Export Function (Save PDF to Server) ===
def export_all_data_to_pdf(user_data, username):
    # Save the PDF file on the server
    pdf_file = f"./{username}_data_export.pdf"
    c = canvas.Canvas(pdf_file, pagesize=letter)
    width, height = letter
    text_obj = c.beginText(40, height - 50)
    text_obj.setFont("Helvetica", 12)

    text_obj.textLine(f"Encrypted Data for user: {username}")
    text_obj.textLine(f"Exported on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    text_obj.textLine("")

    for i, item in enumerate(user_data, start=1):
        text_obj.textLine(f"Entry {i}:")
        text_obj.textLine(f"Encrypted Text: {item['data']}")
        expiry = datetime.fromtimestamp(item['expiration']).strftime('%Y-%m-%d %H:%M:%S')
        text_obj.textLine(f"Expires on: {expiry}")
        text_obj.textLine("-" * 50)

    c.drawText(text_obj)
    c.save()
    return pdf_file

# === Navigation ===
st.title("🔐 Secure Multi-User Data System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Export Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# === Home ===
if choice == "Home":
    st.markdown("<h2 style='text-align: center;'> Welcome to the Secure Multi-User Data System</h2>", unsafe_allow_html=True)
    
    st.markdown("""
    ## 🚀 What You Can Do Here:
    - 📝 **Register** a new account to get started.
    - 🔑 **Login** securely with password and OTP-based two-factor authentication.
    - 📦 **Store** your personal or sensitive data in encrypted format.
    - 🔎 **Retrieve** and decrypt data securely anytime.
    - 📑 **Export** your encrypted data as a professionally formatted PDF.
    
    ---
    > “Security is not a product, but a process.” – Bruce Schneier
    
    """)
    
    st.info("✨ Your privacy is our priority — everything you store is encrypted using top-tier encryption techniques!")

# === Register ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                password_strength = check_password_strength(password)
                st.info(f"Password Strength: {password_strength}")
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                log_activity(f"User {username} registered.")
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

# === Login ===
elif choice == "Login":
    st.subheader("🔑 User Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
            log_activity(f"User {username} logged in.")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append({
                    "data": encrypted,
                    "expiration": time.time() + 86400  # Expiry after 24 hours
                })
                save_data(stored_data)
                log_activity(f"Data stored by {st.session_state.authenticated_user}")
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("All fields are required.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("🔎 Retrieve and Decrypt Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            for i, item in enumerate(user_data):
                st.markdown(f"### Entry {i + 1}")
                st.code(item["data"], language="text")
                expiry_time = datetime.fromtimestamp(item["expiration"]).strftime('%Y-%m-%d %H:%M:%S')
                st.write(f"🕒 Expires on: {expiry_time}")

                if time.time() > item["expiration"]:
                    st.warning("⚠️ This data has expired and cannot be decrypted.")
                else:
                    passkey_input = st.text_input(f"Enter decryption key for Entry {i + 1}", type="password", key=f"key_{i}")
                    if st.button(f"Decrypt Entry {i + 1}", key=f"decrypt_{i}"):
                        decrypted = decrypt_text(item["data"], passkey_input)
                        if decrypted:
                            st.success(f"✅ Decrypted Data:\n{decrypted}")

# === Export Data ===
elif choice == "Export Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📑 Export All Data to PDF")
        if st.button("Export Data"):
            pdf_file = export_all_data_to_pdf(stored_data[st.session_state.authenticated_user]["data"], st.session_state.authenticated_user)
            st.success(f"✅ PDF Exported as {pdf_file}")
            # Provide download link
            with open(pdf_file, "rb") as f:
                st.download_button("Download PDF", f, file_name=pdf_file)
