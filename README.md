# AES128 GPU and CPU Combined Process

This project provides a robust solution for encrypting and decrypting files within a specified folder using AES encryption with a hybrid CPU-GPU approach for optimized performance. The encryption key is derived using the HKDF (HMAC-based Key Derivation Function) combined with the scrypt algorithm for added security.

## Features

- **Hybrid CPU-GPU Processing**: Automatically adjusts the workload between CPU and GPU based on system resource usage.
- **AES Encryption**: Utilizes AES encryption with Electronic Codebook (ECB) mode for file security.
- **HKDF-Scrypt Key Derivation**: Combines HKDF and scrypt for secure key derivation.
- **System Resource Monitoring**: Monitors CPU and memory usage to optimize encryption/decryption processes.
- **Cross-Platform Compatibility**: Runs on systems with or without GPU support.

## Requirements

- Python 3.7 or higher
- Required Python packages:
  - hashlib
  - hmac
  - scrypt
  - secrets
  - psutil
  - pycryptodome
  - torch
  - torchcsprng
  - numpy

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/heshan-basnayaka/cpu-gpu-combined-encryption-algorithm-aes128.git
   cd cpu-gpu-combined-encryption-algorithm-aes128

2. CInstall the required packages:
   ```sh
   pip install hashlib hmac scrypt secrets psutil pycryptodome torch torchcsprng numpy

## Usage

### Encryption and Decryption

#### Setup Parameters:
Update the parameters in the main section of the script according to your requirements:

- `password`: Your encryption password.
- `salt`: A 32-character hexadecimal string.
- `length`: Desired key length in bytes.
- `n`, `r`, `p`: Parameters for the scrypt algorithm.
- `folder_path`: Path to the folder containing files to be encrypted/decrypted.
- `mode`: Set to `'encrypt'` or `'decrypt'`.

#### Run the Script:
```sh
python your_script_name.py
```
### Example

Update the following section in the script with your details:

```python
password = "yourpassword"
salt = "12345678901234567890123456789012"
length = 16
n = 2**10
r = 8
p = 5
folder_path = "path_to_your_folder"
mode = 'encrypt'  # or 'decrypt'
```
Execute the script to start the encryption or decryption process. The script will automatically adjust the workload between CPU and GPU and monitor system resources during the process.

### Output

- Encrypted files will have their contents replaced with encrypted data.
- Decrypted files will have their contents restored to their original form.
- A file named `backup_key.txt` will store the base64 encoded derived key when in encryption mode.

### Monitor System Resources

The script monitors CPU and memory usage to determine the optimal ratio of workload distribution between CPU and GPU. This ensures efficient utilization of system resources.

### Hybrid CPU-GPU Encryption

Depending on the system's GPU availability and resource usage, the script will divide the encryption workload between CPU and GPU. If no GPU is available, it will default to using only the CPU.

### Key Storage

In encryption mode, the derived key will be encoded using base64 and stored in a file named `backup_key.txt`. This file should be securely stored as it is necessary for decrypting the files.

## License

This project is open-sourced under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Acknowledgments

- PyCryptodome for AES encryption support.
- PyTorch and torchcsprng for GPU-based cryptographic operations.
- psutil for system resource monitoring.

## Contact

For any questions or suggestions, please contact [heshankb@gmail.com].
