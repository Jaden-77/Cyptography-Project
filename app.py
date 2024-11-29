from flask import Flask, render_template, request, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import random
from docx import Document

app = Flask(__name__)

# Generate RSA Key Pair
def generate_key_pair():
    if not os.path.exists('keys'):
        os.makedirs('keys')

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('keys/private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)
    with open('keys/public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)

def encrypt_file(file_path, key_path, output_file_path):
    print(f"Starting encryption process for file: {file_path}")
    
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())
        print("RSA public key successfully loaded.")

    # Generate a random symmetric AES key
    symmetric_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)
    print(f"Generated symmetric AES key: {symmetric_key}")
    print(f"Encrypted symmetric AES key: {enc_symmetric_key}")

    # Use AES to encrypt the file content
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
        print(f"Plaintext read from file: {plaintext[:100]}...")  # Print the first 100 bytes
        ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    print(f"Ciphertext (AES) generated: {ciphertext[:100]}...")  # Print the first 100 bytes
    print(f"Nonce: {cipher_aes.nonce}")
    print(f"Tag: {tag}")

    # Apply Caesar cipher to the base64-encoded ciphertext
    base64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    caesar_ciphertext = caesar_encrypt(base64_ciphertext, 3)
    print(f"Ciphertext after Caesar cipher: {caesar_ciphertext[:100]}...")  # Print the first 100 characters

    # Apply Vigenère cipher to the result of Caesar cipher
    vigenere_ciphertext = vigenere_encrypt(caesar_ciphertext, 'KEY')
    print(f"Ciphertext after Vigenère cipher: {vigenere_ciphertext[:100]}...")  # Print the first 100 characters

    # Write all encrypted parts to the output file
    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(enc_symmetric_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(vigenere_ciphertext.encode('utf-8'))
    print(f"Encryption completed and saved to {output_file_path}")

def decrypt_file(file_path, key_path, output_file_path):
    print(f"Starting decryption process for file: {file_path}")

    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())
        print("RSA private key successfully loaded.")

    # Read encrypted content
    with open(file_path, 'rb') as encrypted_file:
        enc_symmetric_key = encrypted_file.read(256)
        print("Encrypted symmetric key read.")
        nonce = encrypted_file.read(16)
        print(f"Nonce: {nonce}")
        tag = encrypted_file.read(16)
        print(f"Tag: {tag}")
        vigenere_ciphertext = encrypted_file.read().decode('utf-8')
        print("Final Vigenère ciphertext read from the file.")

    # Decrypt the symmetric AES key using RSA
    cipher_rsa = PKCS1_OAEP.new(key)
    try:
        symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)
        print("Symmetric AES key successfully decrypted.")
    except ValueError as e:
        print(f"Error during RSA decryption of symmetric key: {e}")
        return None

    try:
        # Reverse Vigenère cipher
        vigenere_decrypted = vigenere_decrypt(vigenere_ciphertext, 'KEY')
        print("Vigenère decryption successful.")

        # Reverse Caesar cipher
        caesar_decrypted = caesar_decrypt(vigenere_decrypted, 3)
        print("Caesar decryption successful.")

        # Decode from base64
        decoded_ciphertext = base64.b64decode(caesar_decrypted)
        print("Base64 decoding successful.")

        # Use AES to decrypt the file content with the symmetric key
        cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        decrypted_bytes = unpad(cipher_aes.decrypt_and_verify(decoded_ciphertext, tag), AES.block_size)
        print("AES decryption and integrity check successful.")

        # Write the decrypted content to the output file
        with open(output_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_bytes)
        print(f"Decryption completed and saved to {output_file_path}.")
    except Exception as e:
        print(f"Error during the decryption chain: {e}")
        return None

# Cipher Functions
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

def vigenere_encrypt(plaintext, keyword):
    ciphertext = ""
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    for p, k in zip(plaintext, keyword_repeated):
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            encrypted_char = chr((ord(p) - base + ord(k) - ord('A')) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += p
    return ciphertext

def vigenere_decrypt(ciphertext, keyword):
    return vigenere_encrypt(ciphertext, ''.join([chr((26 - (ord(k) - ord('A'))) % 26 + ord('A')) for k in keyword])) 

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    operation = request.form['action']
    file = request.files['file']
    filename = 'uploaded_file' + os.path.splitext(file.filename)[-1]
    file_path = os.path.join('uploads', filename)
    file.save(file_path)

    if operation == 'encrypt':
        output_filename = 'encrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        encrypt_file(file_path, 'keys/public_key.pem', output_file_path)
        file_type = 'encrypted'
    elif operation == 'decrypt':
        output_filename = 'decrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        decrypt_file(file_path, 'keys/private_key.pem', output_file_path)
        file_type = 'decrypted'

    return render_template('download.html', operation=operation, filename=output_filename, file_type=file_type)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join('uploads', filename), as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    generate_key_pair()
    app.run(debug=True)
