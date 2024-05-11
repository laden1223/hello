import streamlit as st

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        encrypted_byte = plaintext_byte ^ key_byte
        ciphertext.append(encrypted_byte)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption

st.header("XOR Cipher")

st.write("""
XOR Cipher
---------
The XOR cipher is a simple symmetric encryption algorithm. It works by taking the XOR (exclusive or) of each byte in the plaintext with a corresponding byte in the key. 
""")

input_text = st.text_area("Plain text:")
plaintext = bytes(input_text.encode())

key = st.text_input("Key:")
key = bytes(key.encode())

if st.button("Submit"):
    if plaintext.decode() == key.decode():
        st.error("Plaintext should not be equal to the key")
    elif not plaintext or not key:
        st.error("Invalid key")
    elif len(plaintext.decode()) < len(key.decode()):
        st.error("Plaintext length should be equal or greater than the length of key")
    else:
        encrypted_text = xor_encrypt(plaintext, key)
        decrypted_text = xor_decrypt(encrypted_text, key)
        st.write("Ciphertext:", encrypted_text.decode())
        st.write("Decrypted:", decrypted_text.decode())

