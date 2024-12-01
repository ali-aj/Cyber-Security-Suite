from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import numpy as np
import math
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Utility Functions for Hill Cipher
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def matrix_mod_inv(matrix, modulus):
    det = int(round(np.linalg.det(matrix)))  # Determinant must be integer
    det = det % modulus
    if det == 0:
        raise ValueError("Matrix is not invertible")
    if gcd(det, modulus) != 1:
        raise ValueError("Matrix determinant and modulus are not coprime")
    det_inv = pow(det, -1, modulus)
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    inv_matrix = (det_inv * adjugate) % modulus
    return inv_matrix

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def aes_encrypt(message, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid AES key size. Key must be either 16, 24, or 32 bytes long.")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid AES key size. Key must be either 16, 24, or 32 bytes long.")
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def des_encrypt(message, key):
    if len(key) not in [16, 24]:
        raise ValueError("Invalid TripleDES key size. Key must be either 16 or 24 bytes long.")
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext

def des_decrypt(ciphertext, key):
    if len(key) not in [16, 24]:
        raise ValueError("Invalid TripleDES key size. Key must be either 16 or 24 bytes long.")
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def hill_cipher_encrypt(message, key):
    matrix_size = 3
    modulus = 26
    
    key_matrix = np.array(key).reshape((matrix_size, matrix_size))
    
    try:
        inv_matrix = matrix_mod_inv(key_matrix, modulus)
    except ValueError as e:
        return {"error": str(e)}
    
    message = message.upper().replace(" ", "")
    # Pad message to be multiple of matrix_size
    while len(message) % matrix_size != 0:
        message += 'X'
    
    ciphertext = ""
    for i in range(0, len(message), matrix_size):
        block = np.array([ord(c) - 65 for c in message[i:i+matrix_size]])
        encrypted_block = np.dot(key_matrix, block) % modulus
        ciphertext += ''.join([chr(c + 65) for c in encrypted_block])
    return ciphertext

def hill_cipher_decrypt(ciphertext, key):
    matrix_size = 3
    modulus = 26
    
    key_matrix = np.array(key).reshape((matrix_size, matrix_size))
    
    try:
        inv_matrix = matrix_mod_inv(key_matrix, modulus)
    except ValueError as e:
        return {"error": str(e)}
    
    plaintext = ""
    for i in range(0, len(ciphertext), matrix_size):
        block = np.array([ord(c) - 65 for c in ciphertext[i:i+matrix_size]])
        decrypted_block = np.dot(inv_matrix, block) % modulus
        decrypted_block = decrypted_block.astype(int)
        plaintext += ''.join([chr(c + 65) for c in decrypted_block])
    return plaintext

def generate_elgamal_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters

def elgamal_encrypt(message, public_key, parameters):
    try:
        shared_key = parameters.generate_private_key().exchange(public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        key = digest.finalize()[:32]  # AES-256 requires 32 bytes key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + ciphertext
    except Exception as e:
        return {"error": str(e)}

def elgamal_decrypt(ciphertext, private_key, peer_public_key, parameters):
    try:
        shared_key = private_key.exchange(peer_public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        key = digest.finalize()[:32]  # AES-256 requires 32 bytes key
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        return {"error": str(e)}

def diffie_hellman_key_exchange():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key_a = parameters.generate_private_key()
    public_key_a = private_key_a.public_key()
    private_key_b = parameters.generate_private_key()
    public_key_b = private_key_b.public_key()
    shared_key_a = private_key_a.exchange(public_key_b)
    shared_key_b = private_key_b.exchange(public_key_a)
    assert shared_key_a == shared_key_b
    return shared_key_a.hex()

# Generate ElGamal keys once and reuse
private_key_elgamal, public_key_elgamal, parameters_elgamal = generate_elgamal_keys()

def perform_operation(operation, text, key):
    try:
        if operation == 'rsa_encrypt':
            private_key, public_key = generate_rsa_keys()
            ciphertext = rsa_encrypt(text, public_key)
            return {"result": ciphertext.hex()}
        
        elif operation == 'rsa_decrypt':
            # Replace with actual key retrieval
            private_key, public_key = generate_rsa_keys()
            plaintext = rsa_decrypt(bytes.fromhex(text), private_key)
            return {"result": plaintext}
        
        elif operation == 'aes_encrypt':
            ciphertext = aes_encrypt(text, key.encode())
            return {"result": ciphertext.hex()}
        
        elif operation == 'aes_decrypt':
            plaintext = aes_decrypt(bytes.fromhex(text), key.encode())
            return {"result": plaintext}
        
        elif operation == 'des_encrypt':
            ciphertext = des_encrypt(text, key.encode())
            return {"result": ciphertext.hex()}
        
        elif operation == 'des_decrypt':
            plaintext = des_decrypt(bytes.fromhex(text), key.encode())
            return {"result": plaintext}
        
        elif operation == 'hill_cipher_encrypt':
            key_list = list(map(int, key.split(',')))  # Expecting a comma-separated string of numbers
            ciphertext = hill_cipher_encrypt(text, key_list)
            if isinstance(ciphertext, dict) and 'error' in ciphertext:
                return ciphertext
            return {"result": ciphertext}
        
        elif operation == 'hill_cipher_decrypt':
            key_list = list(map(int, key.split(',')))  # Expecting a comma-separated string of numbers
            plaintext = hill_cipher_decrypt(text, key_list)
            if isinstance(plaintext, dict) and 'error' in plaintext:
                return plaintext
            return {"result": plaintext}
        
        elif operation == 'elgamal_encrypt':
            ciphertext = elgamal_encrypt(text, public_key_elgamal, parameters_elgamal)
            if isinstance(ciphertext, dict) and 'error' in ciphertext:
                return ciphertext
            return {"result": ciphertext.hex()}
        
        elif operation == 'elgamal_decrypt':
            plaintext = elgamal_decrypt(bytes.fromhex(text), private_key_elgamal, public_key_elgamal, parameters_elgamal)
            if isinstance(plaintext, dict) and 'error' in plaintext:
                return plaintext
            return {"result": plaintext}
        
        elif operation == 'diffie_hellman':
            shared_key = diffie_hellman_key_exchange()
            return {"result": shared_key}
        
        else:
            return {"error": "Invalid operation"}
    except Exception as e:
        logger.error(f"Error during {operation}: {str(e)}")
        return {"error": str(e)}