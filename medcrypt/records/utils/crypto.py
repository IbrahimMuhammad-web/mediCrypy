# records/utils/crypto.py

import os
import zlib
import struct
import hashlib
import crc32c
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import rsa

class CryptoError(Exception):
    """Base class for all crypto-related errors"""
    pass

class IntegrityError(CryptoError):
    """Raised when data integrity checks fail"""
    pass

class LegacyFormatDetected(CryptoError):
    """Raised when legacy hex format is detected"""
    pass

def generate_aes_key():
    """Generate a secure AES-256 key"""
    return os.urandom(32)

def generate_rsa_keys():
    """Generate RSA 2048-bit key pair"""
    pub_key, priv_key = rsa.newkeys(2048)
    return pub_key, priv_key

def encrypt_hybrid(plaintext, rsa_pub_key):
    """
    Hybrid encryption using AES-256 for data and RSA-2048 for the AES key
    Returns: {
        'ciphertext': encrypted data,
        'encrypted_key': RSA-encrypted AES key,
        'iv': initialization vector,
        'sha256_hash': SHA-256 hash of plaintext,
        'crc32': CRC32 checksum of plaintext
    }
    """
    if not plaintext:
        raise CryptoError("Empty plaintext provided")
    
    # Generate AES key and IV
    aes_key = generate_aes_key()
    iv = os.urandom(16)
    
    # Compress data first
    compressed_data = zlib.compress(plaintext.encode('utf-8'))
    
    # Calculate integrity checks
    sha256_hash = hashlib.sha256(plaintext.encode('utf-8')).digest()
    crc32_value = crc32c.crc32(plaintext.encode('utf-8'))
    
    # Encrypt with AES
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CFB(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed_data) + encryptor.finalize()
    
    # Encrypt AES key with RSA
    try:
        encrypted_key = rsa.encrypt(aes_key, rsa_pub_key)
    except rsa.pkcs1.CryptoError as e:
        raise CryptoError(f"RSA encryption failed: {str(e)}")
    
    return {
        'ciphertext': ciphertext,
        'encrypted_key': encrypted_key,
        'iv': iv,
        'sha256_hash': sha256_hash,
        'crc32': crc32_value
    }

def decrypt_hybrid(payload, rsa_priv_key):
    """
    Decrypt hybrid encrypted payload with integrity verification
    """
    required_keys = {'ciphertext', 'encrypted_key', 'iv', 'sha256_hash', 'crc32'}
    if not all(key in payload for key in required_keys):
        raise CryptoError("Invalid payload structure")
    
    try:
        # Decrypt AES key with RSA
        aes_key = rsa.decrypt(payload['encrypted_key'], rsa_priv_key)
        
        # Decrypt data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CFB(payload['iv']),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        compressed_data = decryptor.update(payload['ciphertext']) + decryptor.finalize()
        
        # Decompress
        plaintext = zlib.decompress(compressed_data).decode('utf-8')
        
        # Verify integrity
        if crc32c.crc32(plaintext.encode('utf-8')) != payload['crc32']:
            raise IntegrityError("CRC32 checksum verification failed")
        
        if hashlib.sha256(plaintext.encode('utf-8')).digest() != payload['sha256_hash']:
            raise IntegrityError("SHA-256 hash verification failed")
            
        return plaintext
    
    except rsa.pkcs1.CryptoError as e:
        raise CryptoError(f"RSA decryption failed: {str(e)}")
    except zlib.error as e:
        raise IntegrityError(f"Decompression failed: {str(e)}")
    except UnicodeDecodeError as e:
        raise IntegrityError(f"Decoding failed: {str(e)}")

def pack_payload(encrypted_data):
    """
    Pack encrypted data into binary format with metadata:
    [4 bytes - magic][4 bytes - version][4 bytes - payload length][...payload...]
    """
    MAGIC = b'MCRY'
    VERSION = 2  # Current version
    
    # Convert CRC32 to bytes
    crc_bytes = struct.pack('>I', encrypted_data['crc32'])
    
    # Pack all components
    payload = (
        encrypted_data['encrypted_key'] +
        encrypted_data['iv'] +
        encrypted_data['sha256_hash'] +
        crc_bytes +
        encrypted_data['ciphertext']
    )
    
    # Create header
    header = struct.pack('>4sII', MAGIC, VERSION, len(payload))
    
    return header + payload

def unpack_payload(binary_data):
    """
    Unpack binary payload and verify structure
    """
    try:
        # Parse header
        if len(binary_data) < 12:
            raise IntegrityError("Payload too short for header")
        
        magic, version, payload_len = struct.unpack('>4sII', binary_data[:12])
        
        if magic != b'MCRY':
            raise IntegrityError("Invalid magic number")
            
        if version == 1:
            raise LegacyFormatDetected("Legacy hex format detected")
        elif version != 2:
            raise IntegrityError(f"Unsupported version: {version}")
            
        # Check payload length
        if len(binary_data[12:]) != payload_len:
            raise IntegrityError("Payload length mismatch")
            
        payload = binary_data[12:]
        
        # Parse components (fixed sizes)
        key_size = 256  # RSA-2048 encrypted key size
        iv_size = 16
        hash_size = 32  # SHA-256
        crc_size = 4
        
        min_size = key_size + iv_size + hash_size + crc_size
        if len(payload) < min_size:
            raise IntegrityError("Payload too short for components")
            
        encrypted_key = payload[:key_size]
        iv = payload[key_size:key_size+iv_size]
        sha256_hash = payload[key_size+iv_size:key_size+iv_size+hash_size]
        crc_bytes = payload[key_size+iv_size+hash_size:key_size+iv_size+hash_size+crc_size]
        ciphertext = payload[key_size+iv_size+hash_size+crc_size:]
        
        # Convert CRC back to int
        crc32 = struct.unpack('>I', crc_bytes)[0]
        
        return {
            'ciphertext': ciphertext,
            'encrypted_key': encrypted_key,
            'iv': iv,
            'sha256_hash': sha256_hash,
            'crc32': crc32
        }
        
    except struct.error as e:
        raise IntegrityError(f"Invalid payload structure: {str(e)}")