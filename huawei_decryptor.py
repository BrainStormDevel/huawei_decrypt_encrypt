#!/usr/bin/env python3
"""
Huawei Device Configuration Encrytor/Decryptor
Supports AES-256-CBC encryption with GZip compression
"""

import os
import sys
import base64
import hashlib
import argparse
from Crypto.Cipher import AES


def print_ok(msg):
    """Print success message"""
    print(f"[+] {msg}")


def print_error(msg):
    """Print error message"""
    print(f"[-] {msg}")


def print_warn(msg):
    """Print warning message"""
    print(f"[!] {msg}")


def print_info(msg):
    """Print info message"""
    print(f"[*] {msg}")


def derive_aes_key(iv):
    """
    Derive AES-256 key from IV using Huawei algorithm
    
    Algorithm:
    1. Start with digest = IV + 16 zero bytes
    2. Iterate 8192 times: digest = SHA256(digest + key_string)
    3. Return first 32 bytes as AES key
    
    Args:
        iv: 16-byte initialization vector
    
    Returns:
        32-byte AES-256 key or None
    """
    if len(iv) != 16:
        print_error(f"Invalid IV length: {len(iv)} (expected 16)")
        return None
    
    try:
        key_string = bytes.fromhex("13395537D2730554A176799F6D56A239")
        
        # Initialize digest with IV + 16 zeros
        digest = iv + (b'\x00' * 16)
        
        # Iterate 8192 times
        for _ in range(8192):
            digest = hashlib.sha256(digest + key_string).digest()
        
        # Return first 32 bytes as AES key
        return digest[:32]
    
    except Exception as e:
        print_error(f"Key derivation error: {e}")
        return None


def decrypt_aes_cbc_manual(key, iv, ciphertext):
    """
    Manual AES-256-CBC decryption using ECB mode
    
    Args:
        key: 32-byte AES key
        iv: 16-byte initialization vector
        ciphertext: Encrypted data
    
    Returns:
        Decrypted bytes or None if failed
    """
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        
        plaintext = b''
        prev_block = iv
        
        # Decrypt each 16-byte block
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = cipher.decrypt(block)
            
            # XOR with previous ciphertext block for CBC mode
            xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plaintext += xored_block
            prev_block = block
        
        # Remove PKCS7 padding
        pad_len = plaintext[-1]
        if 1 <= pad_len <= 16:
            plaintext = plaintext[:-pad_len]
        
        return plaintext
    
    except Exception as e:
        print_error(f"AES decryption error: {e}")
        return None


def encrypt_aes_cbc_manual(key, iv, plaintext):
    """
    Manual AES-256-CBC encryption using ECB mode
    
    Args:
        key: 32-byte AES key
        iv: 16-byte initialization vector
        plaintext: Data to encrypt
    
    Returns:
        Encrypted bytes or None if failed
    """
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        
        # PKCS7 padding
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        
        ciphertext = b''
        prev_block = iv
        
        # ECB encryption with CBC mode (prev XOR then encrypt)
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted_block = cipher.encrypt(xored_block)
            ciphertext += encrypted_block
            prev_block = encrypted_block
        
        return ciphertext
    except Exception as e:
        print_error(f"AES encryption error: {e}")
        return None


def decompress_data(data):
    """
    Attempt to decompress data using GZip or Deflate
    
    Args:
        data: Compressed bytes
    
    Returns:
        Decompressed string or None if decompression fails
    """
    import zlib
    
    print_info("Decompressing...")
    
    # Try GZip format with zlib (16 + MAX_WBITS for gzip format)
    try:
        decompressed = zlib.decompress(data, 16 + zlib.MAX_WBITS)
        if isinstance(decompressed, bytes):
            decompressed = decompressed.decode('utf-8', errors='ignore')
        print_ok("GZip decompression successful")
        return decompressed
    except Exception as e:
        print_warn(f"GZip decompression failed: {type(e).__name__}")
    
    # Try raw deflate format (-MAX_WBITS)
    try:
        decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
        if isinstance(decompressed, bytes):
            decompressed = decompressed.decode('utf-8', errors='ignore')
        print_ok("Raw Deflate decompression successful")
        return decompressed
    except Exception as e:
        print_warn(f"Raw Deflate decompression failed: {type(e).__name__}")
    
    # Try zlib format (RFC 1950, no wbits parameter)
    try:
        decompressed = zlib.decompress(data)
        if isinstance(decompressed, bytes):
            decompressed = decompressed.decode('utf-8', errors='ignore')
        print_ok("Zlib decompression successful")
        return decompressed
    except Exception as e:
        print_warn(f"Zlib decompression failed: {type(e).__name__}")
    
    return None


def compress_data(data):
    """
    Compress data using GZip
    
    Args:
        data: String or bytes to compress
    
    Returns:
        Compressed bytes or None if compression fails
    """
    import gzip
    
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        compressed = gzip.compress(data)
        return compressed
    except Exception as e:
        print_error(f"Compression error: {e}")
        return None


def encrypt_json(json_data, iv=None):
    """
    Encrypt JSON data to Huawei .conf format
    
    Args:
        json_data: JSON string or file path
        iv: Optional IV (16 bytes). If None, generates random IV
    
    Returns:
        Base64-encoded encrypted data or None if encryption fails
    """
    # Read JSON from file or use string directly
    if isinstance(json_data, str) and os.path.exists(json_data):
        print_info(f"Reading JSON file: {json_data}")
        try:
            with open(json_data, 'r', encoding='utf-8') as f:
                json_str = f.read()
        except Exception as e:
            print_error(f"Failed to read JSON file: {e}")
            return None
    else:
        json_str = json_data
    
    # Compress
    print_info("Compressing with GZip...")
    compressed = compress_data(json_str)
    if not compressed:
        return None
    print_ok(f"Compressed: {len(compressed)} bytes")
    
    # Generate IV if not provided
    if iv is None:
        iv = os.urandom(16)
        print_info(f"Generated random IV: {len(iv)} bytes")
    else:
        print_info(f"Using provided IV: {len(iv)} bytes")
    
    # Derive key
    print_info("Deriving AES key (8192 iterations)...")
    aes_key = derive_aes_key(iv)
    if not aes_key:
        print_error("Key derivation failed")
        return None
    print_ok("Key derived")
    
    # Encrypt
    print_info("Encrypting with AES-256-CBC...")
    encrypted = encrypt_aes_cbc_manual(aes_key, iv, compressed)
    if not encrypted:
        print_error("Encryption failed")
        return None
    print_ok(f"Encrypted: {len(encrypted)} bytes")
    
    # Build final data: 8-byte header + IV + encrypted
    header = b'\x00' * 8
    final_data = header + iv + encrypted
    
    # Base64 encode
    print_info("Encoding with Base64...")
    encoded = base64.b64encode(final_data)
    print_ok(f"Encoded: {len(encoded)} bytes")
    
    return encoded


def decrypt_mode(input_path, output_path):
    """Decrypt .conf file to .xml"""
    print("=== Huawei Configuration Decryptor ===")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print()
    
    # Read input file
    if not os.path.exists(input_path):
        print_error(f"Input file not found: {input_path}")
        return False
    
    print_info("Reading input file...")
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Decode from Base64
    try:
        data = base64.b64decode(data)
        print_ok(f"Decoded: {len(data)} bytes")
    except Exception as e:
        print_error(f"Base64 decoding failed: {e}")
        return False
    
    # Extract IV and encrypted data
    if len(data) < 24:
        print_error("Invalid file format: too short")
        return False
    
    iv = data[8:24]
    encrypted = data[24:]
    
    print_info(f"IV: {len(iv)} bytes")
    print_info(f"Encrypted: {len(encrypted)} bytes")
    print()
    
    # Derive key
    print_info("Deriving AES key (8192 iterations)...")
    aes_key = derive_aes_key(iv)
    if not aes_key:
        print_error("Key derivation failed")
        return False
    print_ok("Key derived")
    
    # Decrypt
    print_info("Decrypting with AES-256-CBC...")
    decrypted = decrypt_aes_cbc_manual(aes_key, iv, encrypted)
    if not decrypted:
        print_error("Decryption failed")
        return False
    print_ok(f"Decrypted: {len(decrypted)} bytes")
    print()
    
    # Decompress
    decompressed = decompress_data(decrypted)
    if not decompressed:
        print_error("Decompression failed")
        return False
    
    # Save output
    print_info("Saving...")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(decompressed)
        print_ok(f"Success: {output_path}")
    except Exception as e:
        print_error(f"Failed to save output: {e}")
        return False
    
    return True


def encrypt_mode(input_path, output_path):
    """Encrypt .xml/.json file to .conf"""
    print("=== Huawei Configuration Encryptor ===")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print()
    
    # Read input file
    if not os.path.exists(input_path):
        print_error(f"Input file not found: {input_path}")
        return False
    
    print_info("Reading input file...")
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            json_data = f.read()
        print_ok(f"Read: {len(json_data)} bytes")
    except Exception as e:
        print_error(f"Failed to read input: {e}")
        return False
    
    print()
    
    # Encrypt
    encoded = encrypt_json(json_data)
    if not encoded:
        return False
    
    # Save output
    print_info("Saving...")
    try:
        with open(output_path, 'wb') as f:
            f.write(encoded)
        print_ok(f"Success: {output_path}")
    except Exception as e:
        print_error(f"Failed to save output: {e}")
        return False
    
    print()
    print_ok("Done!")
    
    return True


def main():
    parser = argparse.ArgumentParser(description='Huawei Device Configuration Encryptor/Decryptor')
    parser.add_argument('--mode', choices=['decrypt', 'encrypt'], default='decrypt',
                        help='Operation mode: decrypt .conf files or encrypt .xml files (default: decrypt)')
    parser.add_argument('-i', '--input', default=None,
                        help='Input file (default: TIM_DN8245X6-8X_20260316_120440.conf for decrypt, or .xml/.json for encrypt)')
    parser.add_argument('-o', '--output', default=None,
                        help='Output file (default: auto-generated from input)')
    
    args = parser.parse_args()
    
    # Set default input based on mode if not provided
    if args.input is None:
        if args.mode == 'decrypt':
            args.input = 'TIM_DN8245X6-8X_20260316_120440.conf'
        else:
            print_error("Encrypt mode requires -i/--input parameter")
            return False
    
    # Auto-generate output filename if not provided
    if args.output is None:
        if args.mode == 'decrypt':
            if args.input.endswith('.conf'):
                args.output = args.input.replace('.conf', '.xml')
            else:
                args.output = args.input + '.xml'
        else:  # encrypt
            if args.input.endswith('.xml'):
                args.output = args.input.replace('.xml', '.conf')
            elif args.input.endswith('.json'):
                args.output = args.input.replace('.json', '.conf')
            else:
                args.output = args.input + '.conf'
    
    if args.mode == 'decrypt':
        return decrypt_mode(args.input, args.output)
    else:  # encrypt
        return encrypt_mode(args.input, args.output)


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

# ============================================================================
# Huawei Configuration Decryptor
# ============================================================================

import sys
import os
import base64
import gzip
import hashlib
import argparse
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[!] Error: pycryptodome is required")
    print("    Install with: pip install pycryptodome")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

    @staticmethod
    def disable_on_windows():
        """Disable colors on Windows if not supported"""
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass


def print_info(message):
    """Print info message"""
    print(f"{Colors.CYAN}[*]{Colors.END} {message}")


def print_ok(message):
    """Print success message"""
    print(f"{Colors.GREEN}[+]{Colors.END} {message}")


def print_warn(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}[-]{Colors.END} {message}")


def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}[!]{Colors.END} {message}")


def derive_aes_key(iv, iterations=8192, key_string="hex:13395537D2730554A176799F6D56A239"):
    """
    Derive AES key from IV using SHA256 (PBKDF-like)
    
    Args:
        iv: Initialization vector (16 bytes)
        iterations: Number of SHA256 iterations
        key_string: Key derivation constant
    
    Returns:
        Derived AES key (32 bytes)
    """
    print_info("Deriving AES key (8192 iterations)...")
    
    key_string_bytes = key_string.encode('ascii')
    # Initialize digest: IV + 16 zero bytes
    digest = iv + bytes(16)
    
    for i in range(iterations):
        combined = digest + key_string_bytes
        digest = hashlib.sha256(combined).digest()
    
    print_ok("Key derived")
    return digest


def decrypt_aes_cbc_manual(encrypted_data, key, iv, block_size=16):
    """
    Decrypt data using AES-256-CBC with manual CBC via ECB blocks
    
    Args:
        encrypted_data: Encrypted bytes
        key: AES key (32 bytes for AES-256)
        iv: Initialization vector (16 bytes)
        block_size: AES block size (16 bytes)
    
    Returns:
        Decrypted bytes
    """
    print_info("Decrypting with AES-256-CBC...")
    
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = bytearray()
    cipher_block_prev = iv
    
    # Process each 16-byte block
    for block_idx in range(0, len(encrypted_data), block_size):
        cipher_block = encrypted_data[block_idx:block_idx + block_size]
        
        # Decrypt using ECB
        decrypted_block = cipher.decrypt(cipher_block)
        
        # XOR with previous ciphertext block (CBC mode)
        for i in range(block_size):
            decrypted_data.append(decrypted_block[i] ^ cipher_block_prev[i])
        
        cipher_block_prev = cipher_block
    
    print_ok(f"Decrypted: {len(decrypted_data)} bytes")
    return bytes(decrypted_data)


def decompress_data(data):
    """
    Attempt to decompress data using GZip or Deflate
    
    Args:
        data: Compressed bytes
    
    Returns:
        Decompressed string or None if decompression fails
    """
    import zlib
    
    print_info("Decompressing...")
    
    # Try GZip format with zlib (16 + MAX_WBITS for gzip format)
    try:
        decompressed = zlib.decompress(data, 16 + zlib.MAX_WBITS)
        if isinstance(decompressed, bytes):
            decompressed = decompressed.decode('utf-8', errors='ignore')
        print_ok("GZip decompression successful")
        return decompressed
    except Exception as e:
        print_warn(f"GZip decompression failed: {type(e).__name__}")
    
    # Try raw deflate format (-MAX_WBITS)
    try:
        decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
        if isinstance(decompressed, bytes):
            decompressed = decompressed.decode('utf-8', errors='ignore')
        print_ok("Raw Deflate decompression successful")
        return decompressed
    except Exception as e:
        print_warn(f"Raw Deflate decompression failed: {type(e).__name__}")
    
    # Try zlib format (RFC 1950, no wbits parameter)
    try:
        decompressed = zlib.decompress(data)
        if isinstance(decompressed, bytes):
            decompressed = decompressed.decode('utf-8', errors='ignore')
        print_ok("Zlib decompression successful")
        return decompressed
    except Exception as e:
        print_warn(f"Zlib decompression failed: {type(e).__name__}")
    
    return None


def decrypt_huawei_config(input_file, output_file=None):
    """
    Main decryption function
    
    Args:
        input_file: Path to encrypted config file
        output_file: Path to save decrypted config (optional)
    
    Returns:
        True if successful, False otherwise
    """
    # Set output path
    if not output_file:
        output_file = os.path.splitext(input_file)[0] + ".xml"
    
    print(f"{Colors.GREEN}=== Huawei Configuration Decryptor ==={Colors.END}")
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print()
    
    # Check file exists
    if not os.path.isfile(input_file):
        print_error(f"File not found: {input_file}")
        return False
    
    # Read and decode
    print_info("Reading input file...")
    try:
        with open(input_file, 'r') as f:
            content = f.read().strip()
        
        binary_data = base64.b64decode(content)
        print_ok(f"Decoded: {len(binary_data)} bytes")
    except Exception as e:
        print_error(f"Failed to decode Base64: {e}")
        return False
    
    # Extract components
    if len(binary_data) < 56:
        print_error("File too small to decrypt")
        return False
    
    iv = binary_data[8:24]  # Bytes 8-23 (16 bytes)
    encrypted_start = 24
    encrypted_end = len(binary_data) - 32  # Leave 32 bytes for HMAC
    encrypted_data = binary_data[encrypted_start:encrypted_end]
    
    print_info(f"IV: {len(iv)} bytes")
    print_info(f"Encrypted: {len(encrypted_data)} bytes")
    print()
    
    # Derive key
    try:
        aes_key = derive_aes_key(iv)
    except Exception as e:
        print_error(f"Key derivation failed: {e}")
        return False
    
    # Decrypt
    try:
        decrypted_data = decrypt_aes_cbc_manual(encrypted_data, aes_key, iv)
    except Exception as e:
        print_error(f"Decryption failed: {e}")
        return False
    
    print()
    
    # Decompress
    decompressed = decompress_data(decrypted_data)
    
    print()
    
    # Save
    print_info("Saving...")
    try:
        if decompressed:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(decompressed)
            print_ok(f"Success: {output_file}")
        else:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            print_warn(f"Saved raw decrypted data to: {output_file}")
    except Exception as e:
        print_error(f"Failed to save output: {e}")
        return False
    
    # Preview
    print()
    print(f"{Colors.YELLOW}Preview:{Colors.END}")
    if decompressed:
        preview = decompressed[:300]
        print(preview)
    else:
        print("(binary data saved)")
    
    print()
    print_ok("Done!")
    return True


def main():
    """Main entry point"""
    Colors.disable_on_windows()
    
    parser = argparse.ArgumentParser(
        description='Decrypt Huawei Optical Network Terminal configuration files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python huawei_decryptor.py config.conf
  python huawei_decryptor.py config.conf -o output.xml
  python huawei_decryptor.py -i TIM_DN8245X6.conf -o decrypted.xml
        '''
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        default='TIM_DN8245X6-8X.conf',
        help='Input encrypted config file (Base64-encoded)'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_file',
        default=None,
        help='Output decrypted config file (default: input with .xml extension)'
    )
    
    parser.add_argument(
        '-i', '--input',
        dest='input_file_arg',
        help='Input file (alternative to positional argument)'
    )
    
    args = parser.parse_args()
    
    # Use -i if provided, otherwise use positional argument
    input_file = args.input_file_arg if args.input_file_arg else args.input_file
    output_file = args.output_file
    
    success = decrypt_huawei_config(input_file, output_file)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
