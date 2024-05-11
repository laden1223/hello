import streamlit as st


st.header("XOR Cipher")


input_text =st.text_area("Plain text:")
plaintext = bytes(input_text.encode())


key = st.text_input("key:")
key = bytes(key.encode())


if st.button("Submit:"):

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