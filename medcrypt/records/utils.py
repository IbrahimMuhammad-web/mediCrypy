import rsa
import time
import tracemalloc
from PIL import Image
import os
import math
import numpy as np

def generate_rsa_keys():
    """Generate RSA public and private keys (2048-bit)"""
    (pub_key, priv_key) = rsa.newkeys(2048)
    return pub_key, priv_key

def rsa_encrypt(text, pub_key):
    """Encrypt text using RSA public key"""
    return rsa.encrypt(text.encode('utf-8'), pub_key)

def rsa_decrypt(encrypted_data, priv_key):
    """Decrypt text using RSA private key"""
    return rsa.decrypt(encrypted_data, priv_key).decode('utf-8')

def text_to_binary(text):
    """Convert text to binary string"""
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_str):
    """Convert binary string to text"""
    return ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))

def int_to_binary(n, bits=8):
    """Convert integer to binary string with specified bits"""
    return format(n, '0{}b'.format(bits))

def binary_to_int(binary_str):
    """Convert binary string to integer"""
    return int(binary_str, 2)

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    data_size = len(data)
    freq_dict = {}
    
    for byte in data:
        freq_dict[byte] = freq_dict.get(byte, 0) + 1
    
    for freq in freq_dict.values():
        probability = freq / data_size
        entropy -= probability * math.log2(probability)
    
    return entropy

def embed_lsb(image_path, data, output_path):
    """Embed data into image using LSB steganography"""
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    binary_data = text_to_binary(data)
    data_len = len(binary_data)
    
    # Check if image can hold the data
    max_data_size = width * height * 3  # 3 channels (RGB)
    if data_len > max_data_size:
        raise ValueError("Image too small to hold the data")
    
    # Convert image to numpy array for faster manipulation
    img_array = np.array(img)
    data_index = 0
    
    for y in range(height):
        for x in range(width):
            if data_index >= data_len:
                break
            
            # Get pixel values
            r, g, b = img_array[y, x]
            
            # Modify LSBs
            if data_index < data_len:
                r = (r & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < data_len:
                g = (g & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < data_len:
                b = (b & 0xFE) | int(binary_data[data_index])
                data_index += 1
            
            # Update pixel
            img_array[y, x] = [r, g, b]
    
    # Save the stego image
    stego_img = Image.fromarray(img_array)
    stego_img.save(output_path)
    return output_path

def extract_lsb(image_path, data_length_bits):
    """Extract data from image using LSB steganography"""
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    img_array = np.array(img)
    binary_data = []
    data_index = 0
    
    for y in range(height):
        for x in range(width):
            if data_index >= data_length_bits:
                break
            
            r, g, b = img_array[y, x]
            
            # Extract LSBs
            if data_index < data_length_bits:
                binary_data.append(str(r & 1))
                data_index += 1
            if data_index < data_length_bits:
                binary_data.append(str(g & 1))
                data_index += 1
            if data_index < data_length_bits:
                binary_data.append(str(b & 1))
                data_index += 1
    
    binary_str = ''.join(binary_data)
    return binary_to_text(binary_str)

def measure_performance(test_type, data, image_path=None):
    """Measure performance metrics for encryption/decryption"""
    results = {}
    
    # Generate keys
    pub_key, priv_key = generate_rsa_keys()
    
    # Encryption
    tracemalloc.start()
    start_time = time.time()
    
    if test_type == 'RSA':
        encrypted_data = rsa_encrypt(data, pub_key)
    elif test_type == 'RSA_LSB':
        encrypted_data = rsa_encrypt(data, pub_key)
        temp_img_path = 'temp_stego.png'
        embed_lsb(image_path, encrypted_data.hex(), temp_img_path)
        with open(temp_img_path, 'rb') as f:
            encrypted_data = f.read()
        os.remove(temp_img_path)
    
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    results['encryption_time'] = end_time - start_time
    results['encryption_memory'] = peak / (1024 * 1024)  # Convert to MB
    
    # Calculate throughput (bytes per second)
    data_size = len(data.encode('utf-8'))
    results['encryption_throughput'] = data_size / results['encryption_time'] if results['encryption_time'] > 0 else 0
    
    # Calculate entropy before/after
    results['entropy_before'] = calculate_entropy(data.encode('utf-8'))
    results['entropy_after'] = calculate_entropy(encrypted_data)
    
    # Decryption
    tracemalloc.start()
    start_time = time.time()
    
    if test_type == 'RSA':
        decrypted_data = rsa_decrypt(encrypted_data, priv_key)
    elif test_type == 'RSA_LSB':
        temp_img_path = 'temp_stego.png'
        with open(temp_img_path, 'wb') as f:
            f.write(encrypted_data)
        extracted_data = extract_lsb(temp_img_path, len(encrypted_data.hex()) * 8)
        decrypted_data = rsa_decrypt(bytes.fromhex(extracted_data), priv_key)
        os.remove(temp_img_path)
    
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    results['decryption_time'] = end_time - start_time
    results['decryption_memory'] = peak / (1024 * 1024)  # Convert to MB
    results['decryption_throughput'] = data_size / results['decryption_time'] if results['decryption_time'] > 0 else 0
    
    # Avalanche effect (compare original and modified data encryption)
    if len(data) > 1:
        modified_data = data[:-1] + ('a' if data[-1] != 'a' else 'b')
        encrypted_modified = rsa_encrypt(modified_data, pub_key)
        
        # Convert to binary strings
        orig_bin = ''.join(format(b, '08b') for b in rsa_encrypt(data, pub_key))
        mod_bin = ''.join(format(b, '08b') for b in encrypted_modified)
        
        # Calculate difference
        diff = sum(1 for a, b in zip(orig_bin, mod_bin) if a != b)
        results['avalanche_effect'] = (diff / len(orig_bin)) * 100
    else:
        results['avalanche_effect'] = 0
    
    return results