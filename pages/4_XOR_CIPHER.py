import streamlit as st
import hashlib

# Symmetric Encryption Algorithms
def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        encrypted_byte = plaintext_byte ^ key_byte
        ciphertext.append(encrypted_byte)
    return ciphertext

def caesar_cipher_encrypt(plaintext, shift):
    """Encrypts plaintext using Caesar Cipher with the given shift."""
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shifted_char = chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 + shift) % 26 + 97)
            ciphertext += shifted_char
        else:
            ciphertext += char
    return ciphertext

def aes_encrypt(plaintext, key):
    """Encrypts plaintext using AES encryption with the given key."""
    # Pad the plaintext if its length is not a multiple of 16 bytes (AES block size)
    plaintext = _pad(plaintext)
    
    # Split the key into 16-byte blocks
    key_blocks = [key[i:i+16] for i in range(0, len(key), 16)]
    
    # Perform AES encryption on each block of plaintext
    ciphertext = b""
    for block in plaintext_blocks:
        # Perform encryption using the current block and key
        encrypted_block = _aes_block_encrypt(block, key)
        ciphertext += encrypted_block
    
    return ciphertext

def _pad(data):
    """Pads the data with PKCS7 padding."""
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def _aes_block_encrypt(block, key):
    """Encrypts a single block of data using AES."""
    # Placeholder for AES encryption algorithm
    return b""
# Asymmetric Encryption Algorithms
def rsa_encrypt(plaintext, public_key):
    """Encrypts plaintext using RSA encryption with the given public key."""
    # Implementation of RSA encryption algorithm here
    pass

def ecc_encrypt(plaintext, public_key):
    """Encrypts plaintext using Elliptic Curve Cryptography with the given public key."""
    # Implementation of ECC encryption algorithm here
    pass

# Hashing Functions
def md5_hash(data):
    """Computes the MD5 hash of the input data."""
    return hashlib.md5(data).hexdigest()

def sha256_hash(data):
    """Computes the SHA-256 hash of the input data."""
    return hashlib.sha256(data).hexdigest()

def sha512_hash(data):
    """Computes the SHA-512 hash of the input data."""
    return hashlib.sha512(data).hexdigest()

def blake2b_hash(data):
    """Computes the BLAKE2b hash of the input data."""
    return hashlib.blake2b(data).hexdigest()

# Streamlit UI
st.title("Cryptographic Toolbox")

selected_option = st.sidebar.selectbox("Select Cryptographic Operation", 
                                       ["Symmetric Encryption", "Asymmetric Encryption", "Hashing"])

if selected_option == "Symmetric Encryption":
    st.header("Symmetric Encryption")

    st.subheader("XOR Cipher")
    # XOR Cipher implementation...
    
    st.subheader("Caesar Cipher")
    # Change the ID of the text area to make it unique
    input_text_caesar = st.text_area("Plain text - Caesar Cipher:")
    shift_caesar = st.number_input("Shift - Caesar Cipher:", min_value=1, max_value=25, value=3)
    if st.button("Encrypt using Caesar Cipher"):
        encrypted_text_caesar = caesar_cipher_encrypt(input_text_caesar, shift_caesar)
        st.write("Ciphertext:", encrypted_text_caesar)

elif selected_option == "Asymmetric Encryption":
    st.header("Asymmetric Encryption")

    st.subheader("RSA Encryption")
    st.write("""
    RSA (Rivest-Shamir-Adleman) is one of the first public-key cryptosystems and is widely used for secure data transmission. It involves the use of a public key for encryption and a private key for decryption.
    """)
    # Add UI elements for RSA encryption here

    st.subheader("Elliptic Curve Cryptography (ECC)")
    st.write("""
    Elliptic Curve Cryptography (ECC) is a public-key cryptography algorithm based on the algebraic structure of elliptic curves over finite fields.
    """)
    # Add UI elements for ECC encryption here

    # Add more asymmetric encryption algorithms here

elif selected_option == "Hashing":
    st.header("Hashing")

    st.subheader("MD5 Hash")
    st.write("""
    MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value.
    """)
    input_text_md5 = st.text_area("Data:")
    if st.button("Compute MD5 Hash"):
        md5_result = md5_hash(input_text_md5.encode())
        st.write("MD5 Hash:", md5_result)

    st.subheader("SHA-256 Hash")
    st.write("""
    SHA-256 (Secure Hash Algorithm 256-bit) is one of the cryptographic hash functions designed by the NSA.
    """)
    input_text_sha256 = st.text_area("Data:")
    if st.button("Compute SHA-256 Hash"):
        sha256_result = sha256_hash(input_text_sha256.encode())
        st.write("SHA-256 Hash:", sha256_result)

    # Add more hashing functions here
    def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, st.writeing bits involved."""

    ciphertext = bytearray()
    
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        encrypted_byte = plaintext_byte^key_byte
        ciphertext.append(encrypted_byte)

        st.write(f"Plaintext byte: {format(plaintext_byte, '08b')} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")
        st.write(f"XOR result:     {format(encrypted_byte, '08b')} = {chr(encrypted_byte)}")
        st.write("--------------------")
        
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption





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
st.balloons()
st.snow()
