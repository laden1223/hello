import streamlit as st
import rsa
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# XOR Cipher functions
def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = b''
    for i in range(len(plaintext)):
        ciphertext += bytes([plaintext[i] ^ key[i % len(key)]])
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)  # XOR encryption is its own decryption

# Caesar Cipher functions
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

# AES Encryption functions
def aes_encrypt(plaintext, key):
    """Encrypts plaintext using AES encryption with the given key."""
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def aes_decrypt(ciphertext, key):
    """Decrypts ciphertext using AES decryption with the given key."""
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Streamlit UI
st.title("Cryptographic Toolbox")

selected_algorithm = st.sidebar.selectbox("Select Cryptographic Algorithm",
                                          ["XOR Cipher", "Caesar Cipher", "AES", "RSA", "MD5", "SHA256", "SHA512", "BLAKE2b"])

if selected_algorithm == "XOR Cipher":
    st.header("XOR Cipher")
    st.write("""
    The XOR cipher is a simple symmetric encryption algorithm. It works by taking the XOR (exclusive or) of each byte in the plaintext with a corresponding byte in the key.
    """)

    input_text = st.text_area("Plain text:")
    plaintext = bytes(input_text.encode())

    key = st.text_input("Key:")
    key = bytes(key.encode())

    if st.button("Encrypt", key="xor_encrypt"):
        if plaintext.decode() == key.decode():
            st.write("Plaintext should not be equal to the key")
        elif not plaintext or not key:
            st.write("Invalid key")
        elif len(plaintext.decode()) < len(key.decode()):
            st.write("Plaintext length should be equal or greater than the length of key")
        else:
            encrypted_text = xor_encrypt(plaintext, key)
            st.write("Ciphertext:", encrypted_text.decode('latin1'))
            decrypted_text = xor_decrypt(encrypted_text, key)
            st.write("Decrypted:", decrypted_text.decode())

elif selected_algorithm == "Caesar Cipher":
    st.header("Caesar Cipher")
    st.write("""
    The Caesar cipher is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.
    """)

    input_text = st.text_area("Plain text:")
    shift = st.number_input("Shift:", min_value=-26, max_value=26, step=1)

    if st.button("Encrypt", key="caesar_encrypt"):
        encrypted_text = caesar_cipher_encrypt(input_text, shift)
        st.write("Ciphertext:", encrypted_text)

    if st.button("Decrypt", key="caesar_decrypt"):
        decrypted_text = caesar_cipher_decrypt(input_text, shift)
        st.write("Decrypted:", decrypted_text)

elif selected_algorithm == "AES":
    st.header("AES")
    st.write("""
    Advanced Encryption Standard (AES) is a symmetric encryption algorithm. It is widely used to secure sensitive data. AES operates on fixed-size blocks and requires a key of a specified length.
    """)

    input_text = st.text_area("Plain text:")
    plaintext = bytes(input_text.encode())

    key = st.text_input("Key (16/24/32 bytes in hex):")
    key = bytes.fromhex(key)

    if st.button("Encrypt", key="aes_encrypt"):
        ciphertext = aes_encrypt(plaintext, key)
        st.write("Ciphertext (hex):", ciphertext.hex())

    if st.button("Decrypt", key="aes_decrypt"):
        ciphertext = bytes.fromhex(st.text_input("Ciphertext (hex):"))
        decrypted_text = aes_decrypt(ciphertext, key)
        st.write("Decrypted:", decrypted_text.decode())

elif selected_algorithm == "RSA":
    st.header("RSA")
    st.write("""
    RSA is a public-key cryptosystem that is widely used for secure data transmission. It involves the use of a public key for encryption and a private key for decryption.
    """)

    input_text = st.text_area("Plain text:")

    if st.button("Generate Keys", key="rsa_generate_keys"):
        (public_key, private_key) = rsa.newkeys(2048)
        st.write("Public Key:")
        st.code(public_key.save_pkcs1().decode('utf-8'))
        st.write("Private Key:")
        st.code(private_key.save_pkcs1().decode('utf-8'))

    public_key_data = st.text_area("Public Key (PEM):")
    private_key_data = st.text_area("Private Key (PEM):")

    if st.button("Encrypt", key="rsa_encrypt"):
        try:
            public_key = rsa.PublicKey.load_pkcs1(public_key_data.encode('utf-8'))
            ciphertext = rsa.encrypt(input_text.encode(), public_key)
            st.write("Ciphertext (hex):", ciphertext.hex())
        except Exception as e:
            st.write(f"Error loading public key: {e}")

    if st.button("Decrypt", key="rsa_decrypt"):
        try:
            private_key = rsa.PrivateKey.load_pkcs1(private_key_data.encode('utf-8'))
            ciphertext = bytes.fromhex(st.text_input("Ciphertext (hex):"))
            decrypted_text = rsa.decrypt(ciphertext, private_key).decode()
            st.write("Decrypted:", decrypted_text)
        except Exception as e:
            st.write(f"Error loading private key or decrypting: {e}")
