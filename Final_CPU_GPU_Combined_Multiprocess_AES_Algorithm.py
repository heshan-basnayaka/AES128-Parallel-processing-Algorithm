import hashlib
import hmac
import scrypt
import secrets
import os
import time
import re
import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import torch
import torchcsprng as csprng
import numpy as np

def hkdf_scrypt(password, salt, length, n, r, p):
    # HKDF extraction step
    prk = hmac.new(salt.encode(), password.encode(), hashlib.sha256).digest()

    # HKDF expansion step
    info = b'Scrypt key derivation'
    t = b''
    okm = b''
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([len(t) + 1]), hashlib.sha256).digest()
        okm += scrypt.hash(t, salt.encode(), n, r, p, length)

    return okm[:length]


def encrypt_file(file_path, key, ratio, device):
    # Read the file contents
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Workload division according to the ratio between cpu and gpu
    workload_division = int(len(plaintext) * ratio)

    # plaintext for cpu
    cpu_plaintext = plaintext[:workload_division]

    # Generate a random IV (Initialization Vector)
    iv = secrets.token_bytes(AES.block_size)

    # Create AES cipher object with key and mode (ECB)
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the cpu plaintext to match AES block size
    padded_cpu_plaintext = pad(cpu_plaintext, AES.block_size)

    # Encrypt the padded cpu plaintext
    cpu_ciphertext = cipher.encrypt(padded_cpu_plaintext)

    if(ratio != 1): # if GPU is now available, only use CPU
        # Encrypt in GPU

        # transfer key into tensor to use in GPU
        key_array = np.frombuffer(key, dtype=np.uint8)
        gpu_key = torch.from_numpy(key_array)
        gpu_key = gpu_key.to(device)

        # plaintext for gpu
        gpu_plaintext = plaintext[workload_division:]

        # transfer gpu_plaintext into tensor to use in GPU
        gpu_plaintext_array = np.frombuffer(gpu_plaintext, dtype=np.uint8)
        gpu_plaintext_tensor = torch.from_numpy(gpu_plaintext_array)
        gpu_plaintext_tensor = gpu_plaintext_tensor.to(device)

        # Pad the gpu_plaintext_tensor to match AES block size
        padded_gpu_plaintext = pad(gpu_plaintext, 16)

        padded_gpu_plaintext_array = np.frombuffer(padded_gpu_plaintext, dtype=np.uint8)
        padded_gpu_plaintext_tensor = torch.from_numpy(padded_gpu_plaintext_array)
        padded_gpu_plaintext_tensor = padded_gpu_plaintext_tensor.to(device)

        # encrypt padded_gpu_plaintext_tensor in GPU
        gpu_encrypted = torch.empty(len(padded_gpu_plaintext_tensor), dtype=torch.int8, device=device)
        csprng.encrypt(padded_gpu_plaintext_tensor, gpu_encrypted, gpu_key, "aes128", "ecb")

        # transfer gpu_encrypted results into bytes to use in cpu
        gpu_encrypted_numpy = gpu_encrypted.cpu().numpy()
        gpu_ciphertext = gpu_encrypted_numpy.tobytes()

        # merge iv, cpu_ciphertext, gpu_ciphertext
        results = iv + cpu_ciphertext + gpu_ciphertext
    else:
        results = iv + cpu_ciphertext

    # Write the IV and encrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(results)

def decrypt_file(file_path, key, ratio, device):
    # Read the file contents
    with open(file_path, 'rb') as file:
        ciphertext = file.read()

    # Extract the IV and ciphertext from the file
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    # Workload division according to the ratio between cpu and gpu
    workload_division = 16 + (int((len(ciphertext) - 16) * ratio / 16)) * 16

    # ciphertext for cput
    cpu_ciphertext = ciphertext[:workload_division]

    # Create AES cipher object with key and mode (ECB)
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the cpu_ciphertext
    cpu_plaintext = cipher.decrypt(cpu_ciphertext)

    # Unpad the decrypted cpu_plaintext
    cpu_plaintext = unpad(cpu_plaintext, AES.block_size)


    if(ratio != 1): # if GPU is now available, only use CPU
        # Decrypt in GPU

        # transfer key into tensor to use in GPU 
        key_array = np.frombuffer(key, dtype=np.uint8)
        gpu_key = torch.from_numpy(key_array)
        gpu_key = gpu_key.to(device)

        # cipertext for gpu
        gpu_ciphertext = ciphertext[workload_division:]

        # transfer gpu_ciphertext into tensor to use in GPU
        encrypted_input_array = np.frombuffer(gpu_ciphertext, dtype=np.uint8)
        encrypted_input_tensor = torch.from_numpy(encrypted_input_array)
        encrypted_input_tensor = encrypted_input_tensor.to(device)

        # Decrypt encrypted_input_tensor in GPU
        gpu_decrypted = torch.empty_like(encrypted_input_tensor)
        csprng.decrypt(encrypted_input_tensor, gpu_decrypted, gpu_key, "aes128", "ecb")

        # transfer gpu_encrypted results into bytes to use in cpu
        gpu_decrypted_numpy = gpu_decrypted.cpu().numpy()
        gpu_plaintext = gpu_decrypted_numpy.tobytes()

        # Unpad the decrypted gpu_plaintext
        gpu_plaintext = unpad(gpu_plaintext, 16)

        # Merge cpu_plaintext and gpu_plaintext
        results = cpu_plaintext + gpu_plaintext
    else:
        results = cpu_plaintext

    # Write the decrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(results)


def cpu_gpu_ratio():

    #Define the ration between cpu and gpu
    gpu_total = torch.cuda.device_count()

    # Usage CPU
    cpu_percent = psutil.cpu_percent(interval=0.1)

    # Usage RAM
    memory_percent = psutil.virtual_memory().percent

    print(f"CPU Usage: {cpu_percent}% - Memory Usage: {memory_percent}")

    # Set the Ratio between CPU and GPU according to the CPU and RAM Usage
    if(gpu_total == 0):
        ratio = 1
    elif(memory_percent > 90 or cpu_percent > 90):
        ratio = 0.1
    elif(memory_percent > 70 or cpu_percent > 70):
        ratio = 0.3
    elif(memory_percent > 40 or cpu_percent > 40):
        ratio = 0.5
    else:
        ratio = 0.7
    return ratio

    
def encrypt_folder(folder_path, key, mode, ratio, device):
    start_time = time.time()
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if mode == 'encrypt':
                encrypt_file(file_path, key, ratio, device)
                print(f'Encrypted: {file_path}')
            elif mode == 'decrypt':
                decrypt_file(file_path, key, ratio, device)
                print(f'Decrypted: {file_path}')

            # Monitor system resources while processing files
            cpu_percent = psutil.cpu_percent(interval=0.1)  
            memory_percent = psutil.virtual_memory().percent
            print(f"CPU Usage: {cpu_percent}% - Memory Usage: {memory_percent}% -Ratio between CPU and GPU: {ratio}")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution Time: {execution_time:.3f} seconds ({execution_time * 1000:.3f} milliseconds)")

if __name__=='__main__':
    # Define regular expressions for input validation
    password_regex = re.compile(r'^.{8,}$')  # Minimum 8 characters
    salt_regex = re.compile(r'^[a-fA-F0-9]{32}$')  # 32 hexadecimal characters
    folder_path_regex = re.compile(r'^[a-zA-Z0-9_./\\-]+$')  # Alphanumeric, underscore, dot, forward slash, backslash, and hyphen

    # Prompt the user for inputs
    while True:
        try:
            password = "1234567890" # password = input("Enter the password: ")
            if not password_regex.match(password):
                print("Invalid password. Password must be at least 8 characters long.")
                continue

            salt = "12345678901234567890123456789012" # salt = input("Enter the salt: ")
            if not salt_regex.match(salt):
                print("Invalid salt. Salt must be a 32-character hexadecimal string.")
                continue

            length = 16 # length = int(input("Enter the desired key length in bytes: "))
            n = 2^10 # n = int(input("Enter the value for 'n': "))
            r = 8 # r = int(input("Enter the value for 'r': "))
            p = 5 # p = int(input("Enter the value for 'p': "))
            
            
            
            break
        except ValueError:
            print("Invalid input. Please try again.")

    # Prompt the user to input the folder path
    # while True:
        
    #     if not folder_path_regex.match(folder_path):
    #         print("Invalid folder path. Folder path must be alphanumeric and can contain underscore, dot, forward slash, backslash, and hyphen.")
    #         continue
    #     if os.path.isdir(folder_path):
    #         break
    #     else:
    #         print("Invalid folder path. Please try again.")
    #folder_path = input("Enter the folder path: ")
    mode = 'encrypt'
    folder_path = "E:\enc"
    

    # Prompt the user to select the mode: 'encrypt' or 'decrypt'
    # while True:
    #     mode = 'encrypt' #mode = input("Enter the mode ('encrypt' or 'decrypt'): ")
    #     if mode in ['encrypt', 'decrypt']:
    #         breakon
    #     else:
    #         print("Invalid mode. Please try again.")

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    ratio = cpu_gpu_ratio()    

    # Call the hkdf_scrypt function with user inputs
    derived_key = hkdf_scrypt(password, salt, length, n, r, p)

    # Encode the derived key using base64
    encoded_key = base64.b64encode(derived_key).decode()

    if mode == 'encrypt':
        # Store the encoded key in a secure location (e.g., a file or database)
        with open("backup_key.txt", "w") as file:
            file.write(encoded_key)

    # Encrypt or decrypt the files within the folder using AES-256
    encrypt_folder(folder_path, derived_key, mode, ratio, device)