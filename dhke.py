from __future__ import annotations
import argparse
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16  

# Convert Hex String to Bytes
def hex_bytes(s: str) -> bytes:
    s = s.strip()
    if not s:
        return b""
    parts = s.split()
    try:
        return bytes(int(b, 16) for b in parts)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid hex byte in: {s}") from e

# Convert bytes to hex string with spaces
def to_hex_with_spaces(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# Calculate Diffie-Hellman Shared Key: g = (2 ** g_e) - g_c ; N = (2 ** N_e) - N_c ; shared_secret = (gy_modN ** x) mod N
def calculate_shared_key(g_e: int, g_c: int, N_e: int, N_c: int, x: int, gy_modN: int) -> int:
    g = (1 << g_e) - g_c  
    N = (1 << N_e) - N_c
    if N <= 0:
        raise ValueError("Computed modulus N must be positive.")
    if not (1 <= gy_modN < N):
        pass
    return pow(gy_modN, x, N)

# Convert integer to exactly 32 bytes for AES-256
def _key_bytes_from_int(shared_key_int: int, endian: str) -> bytes:
    if shared_key_int < 0:
        raise ValueError("Shared key integer must be non-negative.")
    return shared_key_int.to_bytes(32, endian, signed=False)

# Encrypt plaintext with shared key using AES-256-CBC
def encrypt(plaintext: str, key: int, IV: bytes, endian: str = "little") -> bytes:
    key_bytes = _key_bytes_from_int(key, endian)
    if len(IV) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes for AES-CBC.")
    cipher = AES.new(key_bytes, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plaintext.encode("utf-8"), BLOCK_SIZE))

# Decrypt ciphertext with shared key using AES-256-CBC 
def decrypt(ciphertext: bytes, key: int, IV: bytes, endian: str = "little") -> Tuple[str, bytes]:
    key_bytes = _key_bytes_from_int(key, endian)
    if len(IV) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes for AES-CBC.")

    cipher = AES.new(key_bytes, AES.MODE_CBC, IV)

    try:
        pt_bytes = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except ValueError:
        # Unpadding failed — this happens for big-endian key
        raw = cipher.decrypt(ciphertext)
        return to_hex_with_spaces(raw), raw

    try:
        text = pt_bytes.decode("utf-8", errors="strict")
        return text, pt_bytes
    except UnicodeDecodeError:
        return to_hex_with_spaces(pt_bytes), pt_bytes

# Build Input Argument Parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CSE 539 DH + AES-256 (CBC) tool")
    p.add_argument("--iv", required=True, type=hex_bytes, help="128-bit IV as space-separated hex bytes")
    p.add_argument("--g_e", required=True, type=int, help="Exponent for g: g = 2^g_e - g_c")
    p.add_argument("--g_c", required=True, type=int, help="Correction for g: g = 2^g_e - g_c")
    p.add_argument("--N_e", required=True, type=int, help="Exponent for N: N = 2^N_e - N_c")
    p.add_argument("--N_c", required=True, type=int, help="Correction for N: N = 2^N_e - N_c")
    p.add_argument("--x", required=True, type=int, help="Your secret exponent x")
    p.add_argument("--gy_modN", required=True, type=int, help="Other party's g^y mod N (base-10)")
    p.add_argument("--ciphertext", required=True, type=hex_bytes, help="Ciphertext as space-separated hex bytes")
    p.add_argument("--plaintext", required=True, type=str, help="Plaintext string to encrypt with the shared key")
    p.add_argument("--endian", choices=["little", "big"], default="little", help="Endianness for converting shared secret to 32-byte AES key (default: little)")
    return p

# Main Function
def main() -> None:
    args = build_parser().parse_args()

    # 1. Calculate shared key as integer
    shared_key_int = calculate_shared_key(
        g_e=args.g_e,
        g_c=args.g_c,
        N_e=args.N_e,
        N_c=args.N_c,
        x=args.x,
        gy_modN=args.gy_modN,
    )
    # 2. Decrypt provided ciphertext
    decrypted_repr, decrypted_raw = decrypt(args.ciphertext, shared_key_int, args.iv, endian=args.endian)

    # 3. Encrypt provided plaintext
    encrypted_bytes = encrypt(args.plaintext, shared_key_int, args.iv, endian=args.endian)
    
    # 4. Print results
    print(f"{decrypted_repr}, {to_hex_with_spaces(encrypted_bytes)}")

if __name__ == "__main__":
    main()
