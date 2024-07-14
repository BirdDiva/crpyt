from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# Symmetric Key Cryptography (Fernet)
def generate_symmetric_key():
    key = Fernet.generate_key()
    with open("symmetric.key", "wb") as key_file:
        key_file.write(key)

def load_symmetric_key():
    return open("symmetric.key", "rb").read()

def encrypt_symmetric(message):
    key = load_symmetric_key()
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message

def decrypt_symmetric(encrypted_message):
    key = load_symmetric_key()
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(encrypted_message)
    return decrypted_message.decode()

# Asymmetric Key Cryptography (RSA)
def generate_asymmetric_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    public_key = key.publickey().export_key()
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

def load_asymmetric_keys():
    private_key = RSA.import_key(open("private.pem").read())
    public_key = RSA.import_key(open("public.pem").read())
    return private_key, public_key

def encrypt_asymmetric(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return encrypted_message

def decrypt_asymmetric(encrypted_message, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode()

# Hashing (SHA-256)
def hash_message(message):
    hash_object = SHA256.new(data=message.encode())
    return hash_object.hexdigest()

# Substitution Cipher (Caesar Cipher)
def encrypt_caesar(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            encrypted_message += chr((ord(char) + shift - shift_amount) % 26 + shift_amount)
        else:
            encrypted_message += char
    return encrypted_message

def decrypt_caesar(encrypted_message, shift):
    return encrypt_caesar(encrypted_message, -shift)

# Transposition Cipher (Rail Fence Cipher)
def encrypt_rail_fence(message, key):
    rail = [['\n' for i in range(len(message))] for j in range(key)]
    dir_down = False
    row, col = 0, 0

    for char in message:
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        rail[row][col] = char
        col += 1
        row += 1 if dir_down else -1

    encrypted_message = []
    for i in range(key):
        for j in range(len(message)):
            if rail[i][j] != '\n':
                encrypted_message.append(rail[i][j])
    return "".join(encrypted_message)

def decrypt_rail_fence(encrypted_message, key):
    rail = [['\n' for i in range(len(encrypted_message))] for j in range(key)]
    dir_down = None
    row, col = 0, 0

    for i in range(len(encrypted_message)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(key):
        for j in range(len(encrypted_message)):
            if (rail[i][j] == '*') and (index < len(encrypted_message)):
                rail[i][j] = encrypted_message[index]
                index += 1

    decrypted_message = []
    row, col = 0, 0
    for i in range(len(encrypted_message)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        if rail[row][col] != '*':
            decrypted_message.append(rail[row][col])
            col += 1
        row += 1 if dir_down else -1
    return "".join(decrypted_message)

# Generate keys
generate_symmetric_key()
generate_asymmetric_keys()

# Get user input
message = input("Enter the message you want to encrypt: ")
shift = int(input("Enter the shift for Caesar Cipher: "))
rail_key = int(input("Enter the key for Rail Fence Cipher: "))

# Symmetric encryption and decryption
encrypted_symmetric = encrypt_symmetric(message)
print(f"Symmetrically Encrypted message: {encrypted_symmetric}")
decrypted_symmetric = decrypt_symmetric(encrypted_symmetric)
print(f"Symmetrically Decrypted message: {decrypted_symmetric}")

# Asymmetric encryption and decryption
private_key, public_key = load_asymmetric_keys()
encrypted_asymmetric = encrypt_asymmetric(message, public_key)
print(f"Asymmetrically Encrypted message: {encrypted_asymmetric}")
decrypted_asymmetric = decrypt_asymmetric(encrypted_asymmetric, private_key)
print(f"Asymmetrically Decrypted message: {decrypted_asymmetric}")

# Hashing
hashed_message = hash_message(message)
print(f"Hashed message: {hashed_message}")

# Substitution Cipher (Caesar Cipher)
encrypted_caesar = encrypt_caesar(message, shift)
print(f"Caesar Cipher Encrypted message: {encrypted_caesar}")
decrypted_caesar = decrypt_caesar(encrypted_caesar, shift)
print(f"Caesar Cipher Decrypted message: {decrypted_caesar}")

# Transposition Cipher (Rail Fence Cipher)
encrypted_rail_fence = encrypt_rail_fence(message, rail_key)
print(f"Rail Fence Cipher Encrypted message: {encrypted_rail_fence}")
decrypted_rail_fence = decrypt_rail_fence(encrypted_rail_fence, rail_key)
print(f"Rail Fence Cipher Decrypted message: {decrypted_rail_fence}")

