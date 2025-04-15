# First, install the pycryptodome library if you haven't already:
# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Generate RSA keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save the private and public keys to files
with open('private.pem', 'wb') as f:
    f.write(private_key)
with open('public.pem', 'wb') as f:
    f.write(public_key)

# Function to sign data
def sign_message(message, private_key):
    # Import the private key
    key = RSA.import_key(private_key)
    # Create a hash of the message
    h = SHA256.new(message.encode())
    # Sign the hash
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Function to verify signature
def verify_signature(message, signature, public_key):
    # Import the public key
    key = RSA.import_key(public_key)
    # Create a hash of the message
    h = SHA256.new(message.encode())
    try:
        # Verify the signature
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage
if __name__ == "__main__":
    message = "This is a secret message."
    
    # Sign the message
    signature = sign_message(message, private_key)
    print(f"Signature: {signature.hex()}")
    
    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature valid: {is_valid}")