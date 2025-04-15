# The pycryptodome library in Python provides a simple way to implement AES.
# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Function to encrypt data
def encrypt(data, key):
    # Create a cipher object
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the data to make it a multiple of AES block size
    padded_data = pad(data.encode(), AES.block_size)
    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)
    # Return the ciphertext and the IV (Initialization Vector)
    return cipher.iv, ciphertext

# Function to decrypt data
def decrypt(iv, ciphertext, key):
    # Create a cipher object with the same IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Decrypt the data
    decrypted_data = cipher.decrypt(ciphertext)
    # Unpad the decrypted data and decode it
    return unpad(decrypted_data, AES.block_size).decode()

# Example usage
if __name__ == "__main__":
    # 16-byte key (128 bits)
    key = get_random_bytes(16)
    data = "This is a secret message."
    
    # Encrypt the data
    iv, ciphertext = encrypt(data, key)
    print(f"Ciphertext: {ciphertext.hex()}")
    
    # Decrypt the data
    decrypted_data = decrypt(iv, ciphertext, key)
    print(f"Decrypted data: {decrypted_data}")
