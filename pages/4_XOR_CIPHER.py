import streamlit as st
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def welcome_page():
    st.markdown("<h2>Welcome to Cryptography Toolkit</h2>", unsafe_allow_html=True)
    st.write("This toolkit provides various cryptographic techniques for encryption, decryption, and hashing.")
    st.write("Please select a technique from the sidebar to get started.")

def xor_cipher_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = b''
    for i in range(len(plaintext)):
        ciphertext += bytes([plaintext[i] ^ key[i % len(key)]])
    return ciphertext

def xor_cipher_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_cipher_encrypt(ciphertext, key)  # XOR encryption is its own decryption

def caesar_cipher_encrypt(plaintext, shift):
    """Encrypts plaintext using Caesar Cipher with the given shift."""
    result = ''
    for char in plaintext:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def caesar_cipher_decrypt(ciphertext, shift):
    """Decrypts ciphertext using Caesar Cipher with the given shift."""
    return caesar_cipher_encrypt(ciphertext, -shift)

def aes_encrypt(plaintext, key):
    """Encrypts plaintext using AES encryption with the given key."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def aes_decrypt(ciphertext, key):
    """Decrypts ciphertext using AES decryption with the given key."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext, AES.block_size)

def rsa_encrypt(text, key):
    """Encrypts text using RSA encryption with the given key."""
    public_key = rsa.PublicKey.load_pkcs1(key)
    encrypted_text = rsa.encrypt(text.encode(), public_key)
    return encrypted_text

def rsa_decrypt(text, key):
    """Decrypts text using RSA decryption with the given key."""
    private_key = rsa.PrivateKey.load_pkcs1(key)
    decrypted_text = rsa.decrypt(text, private_key).decode()
    return decrypted_text

def main():
    st.title("Applied Cryptography Application")

    # Description for each cryptographic algorithm
    crypto_descriptions = {
        "XOR Cipher": "The XOR cipher is a simple symmetric encryption algorithm. It works by taking the XOR (exclusive or) of each byte in the plaintext with a corresponding byte in the key.",
        "Caesar Cipher": "The Caesar cipher is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
        "AES": "Advanced Encryption Standard (AES) is a symmetric encryption algorithm. It is widely used to secure sensitive data. AES operates on fixed-size blocks and requires a key of a specified length.",
        "RSA": "RSA is a public-key cryptosystem that is widely used for secure data transmission. It involves the use of a public key for encryption and a private key for decryption."
    }

    # Streamlit UI setup
    crypto_options = ["Homepage", "XOR Cipher", "Caesar Cipher", "AES", "RSA"]
    selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

    if selected_crypto == "Homepage":
        welcome_page()
        return

    if selected_crypto in crypto_descriptions:
        st.sidebar.subheader(selected_crypto)
        st.sidebar.write(crypto_descriptions[selected_crypto])

    if selected_crypto in ["XOR Cipher", "Caesar Cipher", "AES"]:
        input_text = st.text_area("Enter Text")
        if selected_crypto == "Caesar Cipher":
            shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
        elif selected_crypto == "AES":
            key = st.text_input("Enter AES Key (16/24/32 bytes in hex)")
            key = bytes.fromhex(key)

    if selected_crypto == "RSA":
        input_text = st.text_area("Enter Text")
        key_type = st.radio("Select Key Type", ("Public Key", "Private Key"))
        key = st.text_area(f"Enter {key_type} (PEM Format)")

    if st.button("Submit"):
        processed_data = ""
        try:
            if selected_crypto == "XOR Cipher":
                key = st.text_input("Enter XOR Key (in hex)")
                key = bytes.fromhex(key)
                processed_data = xor_cipher_encrypt(input_text.encode(), key).decode()
            elif selected_crypto == "Caesar Cipher":
                processed_data = caesar_cipher_encrypt(input_text, shift_key)
            elif selected_crypto == "AES":
                processed_data = aes_encrypt(input_text.encode(), key).hex()
            elif selected_crypto == "RSA":
                processed_data = ""
                if key_type == "Public Key":
                    processed_data = rsa_encrypt(input_text, key).hex()
                else:
                    processed_data = rsa_decrypt(bytes.fromhex(input_text), key)
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
        else:
            st.write("Processed Data:", processed_data)

if __name__ == "__main__":
    main()