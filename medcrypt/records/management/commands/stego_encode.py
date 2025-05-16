# records/management/commands/stego_encode.py

from django.core.management.base import BaseCommand
from django.conf import settings
from records.utils.crypto import generate_rsa_keys, encrypt_hybrid, pack_payload
from records.utils.stego import embed_data, calculate_capacity
from PIL import Image
import os
import json

class Command(BaseCommand):
    help = 'Test steganography encoding with sample data'

    def add_arguments(self, parser):
        parser.add_argument('image_path', type=str, help='Path to cover image')
        parser.add_argument('output_path', type=str, help='Path to save stego image')

    def handle(self, *args, **options):
        # Generate test data
        test_data = {
            "patient_name": "Test Patient",
            "age": 35,
            "diagnosis": "Hypertension",
            "treatment": "Lisinopril 10mg daily"
        }
        
        # Generate keys
        pub_key, _ = generate_rsa_keys()
        
        # Encrypt
        encrypted = encrypt_hybrid(json.dumps(test_data), pub_key)
        payload = pack_payload(encrypted)
        
        # Check image capacity
        try:
            img = Image.open(options['image_path'])
            capacity = calculate_capacity(img)
            
            if len(payload) > capacity:
                self.stderr.write(
                    f"Error: Image too small. Needs {len(payload)} bytes, has {capacity}"
                )
                return
            
            # Embed data
            stego_img = embed_data(img, payload)
            stego_img.save(options['output_path'])
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully embedded {len(payload)} bytes into {options['output_path']}"
                )
            )
            
        except Exception as e:
            self.stderr.write(f"Error: {str(e)}")