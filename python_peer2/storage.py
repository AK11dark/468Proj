# Use AES-GCM to encrypt files, using passwords for access

import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Password-based key derivation for file encryption
def derive_key_from_password(password, salt=None):
    """Derive an encryption key from a password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = kdf.derive(password.encode())
    return key, salt

# Encrypt file using AES-GCM
def encrypt_file_with_password(file_path, password):
    """Encrypt a file using AES-GCM with a password-derived key"""
    # Read the file
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # Derive key from password
    key, salt = derive_key_from_password(password)
    
    # Generate a random IV (nonce)
    iv = os.urandom(12)  # 96 bits as recommended for GCM
    
    # Create the cipher
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Construct the encrypted file path
    encrypted_path = file_path + '.enc'
    
    # Store the encrypted data and metadata
    metadata = {
        'salt': salt.hex(),
        'iv': iv.hex(),
        'tag': tag.hex(),
    }
    
    # Write the metadata and ciphertext to the encrypted file
    with open(encrypted_path, 'wb') as f:
        # Write metadata as JSON
        metadata_bytes = json.dumps(metadata).encode('utf-8')
        f.write(len(metadata_bytes).to_bytes(4, 'big'))
        f.write(metadata_bytes)
        # Write the ciphertext
        f.write(ciphertext)
    
    # Return the path of the encrypted file
    return encrypted_path

# Decrypt file using AES-GCM
def decrypt_file_with_password(encrypted_path, password, output_path=None):
    """Decrypt a file using AES-GCM with a password-derived key"""
    # If output path is not specified, use the original filename without .enc
    if output_path is None:
        output_path = encrypted_path.rsplit('.enc', 1)[0]
    
    # Read the encrypted file
    with open(encrypted_path, 'rb') as f:
        # Read metadata length
        metadata_len = int.from_bytes(f.read(4), 'big')
        # Read metadata
        metadata_bytes = f.read(metadata_len)
        metadata = json.loads(metadata_bytes.decode('utf-8'))
        
        # Read the ciphertext
        ciphertext = f.read()
    
    # Get metadata values
    salt = bytes.fromhex(metadata['salt'])
    iv = bytes.fromhex(metadata['iv'])
    tag = bytes.fromhex(metadata['tag'])
    
    # Derive key from password and salt
    key, _ = derive_key_from_password(password, salt)
    
    try:
        # Create the cipher for decryption
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        # Decrypt the data
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Write the decrypted data
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return output_path
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Get file content without writing to disk
def get_file_content_with_password(encrypted_path, password):
    """Decrypt a file and return its content without writing to disk"""
    try:
        # Read the encrypted file
        with open(encrypted_path, 'rb') as f:
            # Read metadata length
            metadata_len = int.from_bytes(f.read(4), 'big')
            # Read metadata
            metadata_bytes = f.read(metadata_len)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Read the ciphertext
            ciphertext = f.read()
        
        # Get metadata values
        salt = bytes.fromhex(metadata['salt'])
        iv = bytes.fromhex(metadata['iv'])
        tag = bytes.fromhex(metadata['tag'])
        
        # Derive key from password and salt
        key, _ = derive_key_from_password(password, salt)
        
        # Create the cipher for decryption
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        # Decrypt the data
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Secure storage manager for handling encrypted files
class SecureStorage:
    def __init__(self, storage_dir="Received"):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
    
    def store_encrypted_file(self, file_content, filename, password):
        """Store file content with encryption"""
        temp_path = os.path.join(self.storage_dir, "temp_" + filename)
        
        # Write content to temporary file
        with open(temp_path, 'wb') as f:
            f.write(file_content)
        
        # Encrypt the file
        encrypted_path = encrypt_file_with_password(temp_path, password)
        
        # Remove the temporary file
        os.remove(temp_path)
        
        # Return path to encrypted file
        return encrypted_path
    
    def get_decrypted_file(self, filename, password, output_path=None):
        """Decrypt and return file content"""
        encrypted_path = os.path.join(self.storage_dir, filename)
        if not encrypted_path.endswith('.enc'):
            encrypted_path += '.enc'
            
        if not os.path.exists(encrypted_path):
            print(f"File {encrypted_path} does not exist")
            return None
        
        # Decrypt the file
        return decrypt_file_with_password(encrypted_path, password, output_path)
    
    def get_file_content(self, filename, password):
        """Get decrypted file content without writing to disk"""
        encrypted_path = os.path.join(self.storage_dir, filename)
        if not encrypted_path.endswith('.enc'):
            encrypted_path += '.enc'
            
        if not os.path.exists(encrypted_path):
            print(f"File {encrypted_path} does not exist")
            return None
        
        # Get file content
        return get_file_content_with_password(encrypted_path, password)
    
    def list_encrypted_files(self):
        """List all encrypted files in storage directory"""
        return [f for f in os.listdir(self.storage_dir) if f.endswith('.enc')]
        
    def list_all_files(self):
        """List all files in storage directory with their encryption status"""
        files = os.listdir(self.storage_dir)
        file_info = []
        
        for filename in files:
            is_encrypted = filename.endswith('.enc')
            original_name = filename.rsplit('.enc', 1)[0] if is_encrypted else filename
            
            file_info.append({
                'filename': filename,
                'original_name': original_name,
                'encrypted': is_encrypted
            })
            
        return file_info
