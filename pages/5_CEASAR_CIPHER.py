import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: flag if decrypt or encrypt
    Returns:
        A string containing the encrypted text if encrypt and plain text if decrypt
    """
    
    result =""
    
    if len(shift_keys)<= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")
    
    for i, char in enumerate(text):
        shift = shift_keys[i % len(shift_keys)]
        
        if 32<= ord(char) <=125:
            new_ascii = ord(char) + shift if not ifdecrypt else ord(char) - shift
            while new_ascii > 125:
                new_ascii -=94
            while new_ascii < 32:
                new_ascii += 94
              
            result += chr(new_ascii)
        else:
            result += char
        st.write(i, char, shift, result[i])
        
    return result
    
def main():
    text = st.text_input("Enter text: ")
    shift_keys_input = st.text_input("Enter shift:").split()

    shift_keys = [int(key) for key in shift_keys_input]

    if st.button("Print Output"):
        enc = encrypt_decrypt(text, shift_keys, False)
        dec = encrypt_decrypt(enc, shift_keys, True)
        st.write("----------")
        st.write("Text:", text)
        st.write("Shift keys:", *shift_keys)
        st.write("Cipher:", enc)
        st.write("Decrypted text:", dec)
        st.write("----------")

if __name__ == "__main__":
    main()