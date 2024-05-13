import streamlit as st
import hashlib
import rsa
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Streamlit UI
st.title("Cryptographic Toolbox")

selected_algorithm = st.sidebar.selectbox("Select Cryptographic Algorithm",
                                          ["XOR Cipher", "Caesar Cipher", "AES", "RSA", "MD5", "SHA256", "SHA512", "BLAKE2b"])

if selected_algorithm == "XOR Cipher":
    st.header("XOR Cipher")

    input_text = st.text_area("Plain text:")
    plaintext = bytes(input_text.encode())

    key = st.text_input("key:")
    key = bytes(key.encode())

    if st.button("Submit"):
        if plaintext.decode() == key.decode():
            st.write("Plaintext should not be equal to the key")
        elif not plaintext or not key:
            st.write("Invalid key")
        elif len(plaintext.decode()) < len(key.decode()):
            st.write("Plaintext length should be equal or greater than the length of key")
        else:
            encrypted_text = xor_encrypt(plaintext, key)
            st.write("Ciphertext:", encrypted_text.decode())
            decrypted_text = xor_decrypt(encrypted_text, key)
            st.write("Decrypted:", decrypted_text.decode())

elif selected_algorithm == "Caesar Cipher":
    st.header("Caesar Cipher")

    input_text = st.text_area("Plain text:")
    shift = st.number_input("Shift:")

    if st.button("Submit"):
        encrypted_text = caesar_cipher_encrypt(input_text, shift)
        st.write("Ciphertext:", encrypted_text)

        decrypted_text = caesar_cipher_decrypt(encrypted_text, shift)
        st.write("Decrypted:", decrypted_text)

elif selected_algorithm == "AES":
    st.header("AES")

    input_text = st.text_area("Plain text:")
    plaintext = bytes(input_text.encode())

    key = st.text_input("Key (16/24/32 bytes):")
    key = bytes.fromhex(key)

    if st.button("Encrypt"):
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        st.write("Ciphertext (hex):", ciphertext.hex())

    if st.button("Decrypt"):
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_text = cipher.decrypt(bytes.fromhex(st.text_input("Ciphertext (hex):"))).decode()
        st.write("Decrypted:", decrypted_text)

elif selected_algorithm == "RSA":
    st.header("RSA")

    input_text = st.text_area("Plain text:")

    if st.button("Generate Keys"):
        (public_key, private_key) = rsa.newkeys(2048)
        st.write("Public Key:", base64.b64encode(public_key.save_pkcs1()).decode())
        st.write("Private Key:", base64.b64encode(private_key.save_pkcs1()).decode())

    if st.button("Encrypt"):
        public_key = rsa.PublicKey.load_pkcs1(bytes.fromhex(st.text_input("Public Key (hex):")))
        ciphertext = rsa.encrypt(input_text.encode(), public_key)
        st.write("Ciphertext (hex):", ciphertext.hex())

    if st.button("