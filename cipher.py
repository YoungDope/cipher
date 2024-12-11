import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import os
import io

# Helper functions for Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Helper functions for Vigenere Cipher
def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            shift = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            shift = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - shift_base - shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

# RSA Key Generation
@st.cache_resource
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# RSA Encryption/Decryption
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return base64.b64encode(cipher.encrypt(data)).decode()

def rsa_decrypt(data, private_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher.decrypt(base64.b64decode(data))

# AES Encryption/Decryption
def aes_encrypt(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, cipher.nonce, ciphertext

def aes_decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Streamlit App
st.title("File Encryption and Decryption")

private_key, public_key = generate_rsa_keys()

st.sidebar.title("Options")
mode = st.sidebar.radio("Choose Mode", ["Encrypt", "Decrypt"])

if mode == "Encrypt":
    st.header("Encryption")

    file = st.file_uploader("Upload a file to encrypt", type=None)
    caesar_shift = st.slider("Caesar Cipher Shift", min_value=1, max_value=25, value=3)
    vigenere_key = st.text_input("Vigenere Cipher Key", "KEY")

    if file and st.button("Encrypt File"):
        file_data = file.read()
        original_filename = file.name

        # Step 1: Encrypt file with AES
        aes_key, nonce, aes_encrypted = aes_encrypt(file_data)

        # Step 2: Encrypt AES key with RSA
        rsa_encrypted_key = rsa_encrypt(aes_key, public_key)

        # Step 3: Apply Caesar and Vigenere Ciphers
        metadata = f"{original_filename}::"
        combined_encrypted = metadata + rsa_encrypted_key + "::" + base64.b64encode(nonce + aes_encrypted).decode()
        caesar_encrypted = caesar_encrypt(combined_encrypted, caesar_shift)
        final_encrypted = vigenere_encrypt(caesar_encrypted, vigenere_key)

        encrypted_file_path = f"encrypted_{file.name}.txt"
        with open(encrypted_file_path, "w") as f:
            f.write(final_encrypted)

        st.success("File encrypted successfully!")
        st.download_button(
            label="Download Encrypted File",
            data=final_encrypted,
            file_name=encrypted_file_path,
            mime="text/plain"
        )

elif mode == "Decrypt":
    st.header("Decryption")

    file = st.file_uploader("Upload a file to decrypt", type=None)
    caesar_shift = st.slider("Caesar Cipher Shift", min_value=1, max_value=25, value=3)
    vigenere_key = st.text_input("Vigenere Cipher Key", "KEY")

    if file and st.button("Decrypt File"):
        file_data = file.read().decode()

        # Step 1: Reverse Vigenere Cipher
        vigenere_decrypted = vigenere_decrypt(file_data, vigenere_key)

        # Step 2: Reverse Caesar Cipher
        caesar_decrypted = caesar_decrypt(vigenere_decrypted, caesar_shift)

        try:
            # Step 3: Extract metadata, RSA key, and AES data
            metadata, rsa_encrypted_key, encoded_aes_data = caesar_decrypted.split("::", 2)
            aes_data = base64.b64decode(encoded_aes_data)

            # Step 4: Decrypt RSA key
            aes_key = rsa_decrypt(rsa_encrypted_key, private_key)

            # Step 5: Decrypt AES data
            nonce = aes_data[:16]
            ciphertext = aes_data[16:]
            original_data = aes_decrypt(aes_key, nonce, ciphertext)

            decrypted_file_path = metadata  # Use the original filename from metadata

            with open(decrypted_file_path, "wb") as f:
                f.write(original_data)

            st.success("File decrypted successfully!")
            st.download_button(
                label="Download Decrypted File",
                data=original_data,
                file_name=decrypted_file_path,
                mime="application/octet-stream"
            )
        except Exception as e:
            st.error(f"Decryption failed! Error: {str(e)}")
