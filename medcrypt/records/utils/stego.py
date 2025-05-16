# records/utils/stego.py

import numpy as np
from PIL import Image
import io
import struct
from .crypto import LegacyFormatDetected, IntegrityError

class StegoError(Exception):
    """Base class for steganography errors"""
    pass

class CapacityError(StegoError):
    """Raised when image doesn't have enough capacity"""
    pass

def calculate_capacity(image):
    """Calculate maximum payload capacity in bytes"""
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGB')
    
    width, height = image.size
    capacity = width * height * 3  # 3 channels in RGB
    capacity_bits = capacity  # 1 bit per channel
    return capacity_bits // 8  # Convert to bytes

def embed_data(image, data):
    """
    Embed binary data into image using LSB steganography
    Returns: PIL Image with embedded data
    """
    if not isinstance(data, bytes):
        raise StegoError("Data must be bytes")
    
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGB')
    
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Flatten the data to binary string
    data_len = len(data)
    header = struct.pack('>I', data_len)  # 4-byte length header
    full_data = header + data
    binary_str = ''.join(f'{byte:08b}' for byte in full_data)
    
    # Check capacity
    required_bits = len(binary_str)
    available_bits = img_array.shape[0] * img_array.shape[1] * 3
    if required_bits > available_bits:
        raise CapacityError(
            f"Insufficient capacity: need {required_bits} bits, have {available_bits}"
        )
    
    # Embed data
    data_index = 0
    for y in range(img_array.shape[0]):
        for x in range(img_array.shape[1]):
            for c in range(3):  # RGB channels
                if data_index < len(binary_str):
                    # Clear LSB and set to data bit
                    img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | int(binary_str[data_index])
                    data_index += 1
                else:
                    break
            if data_index >= len(binary_str):
                break
        if data_index >= len(binary_str):
            break
    
    return Image.fromarray(img_array)

def extract_data(image):
    """
    Extract binary data from image using LSB steganography
    Returns: extracted bytes
    """
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGB')
    
    img_array = np.array(image)
    
    # First extract length header (4 bytes = 32 bits)
    length_bits = []
    bits_read = 0
    length_size = 32
    
    for y in range(img_array.shape[0]):
        for x in range(img_array.shape[1]):
            for c in range(3):
                if bits_read < length_size:
                    length_bits.append(str(img_array[y, x, c] & 1))
                    bits_read += 1
                else:
                    break
            if bits_read >= length_size:
                break
        if bits_read >= length_size:
            break
    
    # Convert length bits to bytes
    length_bytes = bytes([
        int(''.join(length_bits[i:i+8]), 2)
        for i in range(0, len(length_bits), 8)
    ])
    data_len = struct.unpack('>I', length_bytes)[0]
    
    # Extract the actual data
    data_bits = []
    bits_read = 0
    total_bits = data_len * 8
    
    for y in range(img_array.shape[0]):
        for x in range(img_array.shape[1]):
            for c in range(3):
                # Skip the length header bits we already read
                if bits_read < (length_size + total_bits) and bits_read >= length_size:
                    data_bits.append(str(img_array[y, x, c] & 1))
                bits_read += 1
    
    # Convert data bits to bytes
    data_bytes = bytes([
        int(''.join(data_bits[i:i+8]), 2)
        for i in range(0, len(data_bits), 8)
    ])
    
    return data_bytes

def is_legacy_hex(data):
    """Check if data appears to be legacy hex format"""
    try:
        # Legacy format was hex-encoded RSA encrypted data
        if len(data) % 2 != 0:
            return False
        if not all(c in '0123456789abcdefABCDEF' for c in data.decode('latin-1')):
            return False
        return True
    except UnicodeDecodeError:
        return False