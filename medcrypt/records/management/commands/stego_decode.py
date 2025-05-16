# records/management/commands/stego_decode.py

from django.core.management.base import BaseCommand
from records.utils.crypto import unpack_payload, decrypt_hybrid
from records.utils.stego import extract_data, is_legacy_hex
from PIL import Image
import json
import rsa

class Command(BaseCommand):
    help = 'Test steganography decoding with sample data'

    def add_arguments(self, parser):
        parser.add_argument('image_path', type=str, help='Path to stego image')
        parser.add_argument('private_key_path', type=str, help='Path to private key file')

    def handle(self, *args, **options):
        try:
            # Load private key
            with open(options['private_key_path'], 'rb') as f:
                priv_key = rsa.PrivateKey.load_pkcs1(f.read())
            
            # Extract data
            img = Image.open(options['image_path'])
            extracted = extract_data(img)
            
            # Check for legacy format
            if is_legacy_hex(extracted):
                self.stdout.write("Legacy hex format detected - using fallback decoder")
                # Fallback to legacy decryption would go here
                self.stderr.write("Legacy decryption not implemented in this example")
                return
            
            # Unpack and decrypt modern format
            payload = unpack_payload(extracted)
            decrypted = decrypt_hybrid(payload, priv_key)
            
            # Print results
            data = json.loads(decrypted)
            self.stdout.write(
                self.style.SUCCESS("Successfully decrypted data:")
            )
            self.stdout.write(json.dumps(data, indent=2))
            
        except Exception as e:
            self.stderr.write(f"Error: {str(e)}")