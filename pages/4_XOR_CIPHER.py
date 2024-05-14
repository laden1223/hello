import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os


def welcome_page():
    st.markdown("<h2>Welcome to Cryptography Toolkit</h2>", unsafe_allow_html=True)
    st.write("This toolkit provides various cryptographic techniques for encryption, decryption, and hashing.")
    st.write("Please select a technique from the sidebar to get started.")


def main():
    st.title("Applied Cryptography Application")

    # Description for each cryptographic algorithm
    crypto_descriptions = {
        "Caesar Cipher": "The Caesar Cipher is one of the simplest and most widely known encryption techniques. It is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
        "Fernet Symmetric Encryption": "Fernet is a symmetric encryption algorithm that uses a shared secret key to encrypt and decrypt data. It provides strong encryption and is easy to use.",
        "RSA Asymmetric Encryption": "RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm that uses a public-private key pair. It is widely used for secure communication and digital signatures.",
        "SHA-1 Hashing": "SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value. It is commonly used for data integrity verification.",
        "SHA-256 Hashing": "SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It is commonly used for data integrity verification.",
        "SHA-512 Hashing": "SHA-512 is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It provides stronger security than SHA-256.",
        "MD5 Hashing": "MD5 is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It is commonly used for checksums and data integrity verification.",
        "Symmetric File Encryption": "Symmetric encryption technique to encrypt and decrypt files using Fernet."
    }

    # Streamlit UI setup
    crypto_options = ["Homepage", "Caesar Cipher", "Fernet Symmetric Encryption", "Symmetric File Encryption", "RSA Asymmetric Encryption", 
                      "SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]
    selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

    if selected_crypto == "Homepage":
        welcome_page()
        return

    if selected_crypto in crypto_descriptions:
        st.sidebar.subheader(selected_crypto)
        st.sidebar.write(crypto_descriptions[selected_crypto])

    if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
        input_text = st.text_area("Enter Text")
        if selected_crypto == "Caesar Cipher":
            shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
        if selected_crypto == "Fernet Symmetric Encryption":
            secret_key = st.text_input("Enter Encryption Key")
        elif selected_crypto == "RSA Asymmetric Encryption":
            encryption_key = st.text_area("Enter Public Key (Encryption) / Private Key (Decryption)")
        decrypt_checkbox = st.checkbox("Decrypt")

    if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
        text_or_file = st.radio("Hash Text or File?", ("Text", "File"))
        if text_or_file == "Text":
            input_text = st.text_area("Enter Text")
        else:
            uploaded_file = st.file_uploader("Upload a file")
        
    if selected_crypto == "Symmetric File Encryption":
        uploaded_file = st.file_uploader("Upload a file")
        secret_key = st.text_input("Enter Encryption Key")
        decrypt_checkbox = st.checkbox("Decrypt")

    if st.button("Submit"):
        processed_data = ""
        try:
            if selected_crypto == "Caesar Cipher":
                processed_data = apply_caesar_cipher(input_text, shift_key, decrypt_checkbox)
            elif selected_crypto == "Fernet Symmetric Encryption":
                processed_data, secret_key, _ = apply_fernet_encryption(input_text, secret_key, decrypt_checkbox)
            elif selected_crypto == "RSA Asymmetric Encryption":
                processed_data = apply_rsa_encryption(input_text, encryption_key, decrypt_checkbox)
            elif selected_crypto == "SHA-1 Hashing":
                if text_or_file == "Text":
                    processed_data = apply_sha1_hash(input_text)
                else:
                    processed_data = apply_file_hash(uploaded_file, "sha1")
            elif selected_crypto == "SHA-256 Hashing":
                if text_or_file == "Text":
                    processed_data = apply_hash_to_text(input_text, "sha256")
                else:
                    processed_data = apply_file_hash(uploaded_file, "sha256")
            elif selected_crypto == "SHA-512 Hashing":
                if text_or_file == "Text":
                    processed_data = apply_hash_to_text(input_text, "sha512")
                else:
                    processed_data = apply_file_hash(uploaded_file, "sha512")
            elif selected_crypto == "MD5 Hashing":
                if text_or_file == "Text":
                    processed_data = apply_hash_to_text(input_text, "md5")
                else:
                    processed_data = apply_file_hash(uploaded_file, "md5")
            elif selected_crypto == "Symmetric File Encryption":
                if uploaded_file is not None:
                    original_filename = uploaded_file.name
                    if decrypt_checkbox:
                        decrypted_data, filename = apply_fernet_file_decryption(uploaded_file, secret_key, original_filename)
                        if decrypted_data:
                            st.download_button("Download Decrypted File", decrypted_data, file_name=filename)
                    else:
                        encrypted_data, file_hash = apply_fernet_file_encryption(uploaded_file, secret_key)
                        if encrypted_data:
                            st.write(f"Encrypted file hash: {file_hash}")
                            st.download_button("Download Encrypted File", encrypted_data, file_name="Encrypted_" + original_filename)
                else:
                   
                    processed_data = "No file uploaded."

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
        else:
            if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
                st.write("Processed Data:", processed_data)
            elif selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
                st.write("Hash Value:", processed_data)


def apply_caesar_cipher(text, shift_key, decrypt_flag):
    """Encrypts or decrypts text using the Caesar Cipher."""
    result = ""
    for char in text:
        if 32 <= ord(char) <= 125:
            shift = shift_key if not decrypt_flag else -shift_key
            new_ascii = ord(char) + shift
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
            result += chr(new_ascii)
        else:
            result += char
    return result


def apply_fernet_encryption(text, key, decrypt_flag):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
    fernet = Fernet(key.encode())
    if decrypt_flag:
        return fernet.decrypt(text.encode()).decode(), None, None
    else:
        return fernet.encrypt(text.encode()).decode(), key, None


def apply_rsa_encryption(text, key, decrypt_flag):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if decrypt_flag:
        try:
            private_key = serialization.load_pem_private_key(
                key.encode(),
                password=None,
                backend=default_backend()
            )
            decrypted_text = private_key.decrypt(
                base64.b64decode(text),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            return decrypted_text
        except Exception as e:
            st.write("Error during decryption:", e)
            return "Decryption Error: " + str(e)
    else:
        public_key = serialization.load_pem_public_key(key.encode())
        encrypted_text = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_text).decode()


def apply_hash_to_text(text, algorithm):
    """Hashes the text using the specified algorithm."""
    return hashlib.new(algorithm, text.encode()).hexdigest()


def apply_sha1_hash(text):
    """Hashes the text using SHA-1."""
    return hashlib.sha1(text.encode()).hexdigest()


def apply_file_hash(file, algorithm):
    """Computes the hash of a file using the specified algorithm."""
    hash_function = hashlib.new(algorithm)
    file.seek(0)  # Ensure we're at the start of the file
    while True:
        data = file.read(65536)  # Read in chunks to conserve memory
        if not data:
            break
        hash_function.update(data)
    file.seek(0)  # Reset file pointer to beginning after hashing
    return hash_function.hexdigest()


def apply_fernet_file_encryption(file, key):
    """Encrypts a file using Fernet symmetric encryption and computes its hash."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
    fernet = Fernet(key.encode())
    encrypted_data = fernet.encrypt(file.read())
    file_hash = hashlib.sha256(encrypted_data).hexdigest()
    return encrypted_data, file_hash


def apply_fernet_file_decryption(file, key, original_filename):
    """Decrypts a file using Fernet symmetric encryption and saves it with the original filename."""
    try:
        fernet = Fernet(key.encode())
        decrypted_data = fernet.decrypt(file.read())
        return decrypted_data, original_filename
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None, None


if __name__ == "__main__":
    main()
