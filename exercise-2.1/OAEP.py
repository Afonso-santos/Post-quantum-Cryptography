import hashlib
import secrets

# =====================================================================
# 1. HELPER BIT & STRING FUNCTIONS
# =====================================================================

def string_to_bits(s: str) -> list[int]:
    """Converts a Latin-1/ASCII string into a list of bits."""
    bits = []
    for char in s.encode('latin-1'):
        for i in range(7, -1, -1):
            bits.append((char >> i) & 1)
    return bits

def bits_to_bytes(bits: list[int]) -> bytearray:
    """Converts bits to a bytearray."""
    byte_vals = bytearray()
    for i in range(0, len(bits) - (len(bits) % 8), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        byte_vals.append(byte)
    return byte_vals

def bits_to_int(bits: list[int]) -> int:
    val = 0
    for bit in bits:
        val = (val << 1) | bit
    return val

def convert_to_bits(val: int, length: int) -> list[int]:
    return [(val >> i) & 1 for i in range(length - 1, -1, -1)]

def xor(a: list[int], b: list[int]) -> list[int]:
    assert len(a) == len(b), f"Length mismatch: {len(a)} != {len(b)}"
    return [aa ^ bb for aa, bb in zip(a, b)]

def hash_bits(bits: list[int], out_len: int) -> list[int]:
    """MGF1 mask generator using SHA-256."""
    data = bits_to_bytes(bits)
    derived = []
    counter = 0
    while len(derived) < out_len:
        digest = hashlib.sha256(data + counter.to_bytes(4, 'big')).digest()
        for byte in digest:
            for shift in range(7, -1, -1):
                derived.append((byte >> shift) & 1)
        counter += 1
    return derived[:out_len]


# =====================================================================
# 2. OAEP PADDING & RSA BLOCK PRIMITIVES
# =====================================================================

def oaep_pad(message: list[int], nonce: list[int], g: int, h: int) -> list[int]:
    """
    Mathematical Construction:
        1. mm = m || 0^(g - |m|)   in {0, 1}^g      (Zero-padding redundancy)
        2. G  = mm XOR hash_1(r)   in {0, 1}^g      (Mask message)
        3. H  = r  XOR hash_2(G)   in {0, 1}^h      (Mask nonce)
        4. OAEP(m, r) = G || H     in {0, 1}^(g+h)  (Concatenation)
    """
    assert len(message) <= g, f"Message ({len(message)} bits) exceeds g ({g} bits)"
    assert len(nonce) == h, f"Nonce must be exactly h ({h}) bits"
    mm = message + [0] * (g - len(message))
    G = xor(mm, hash_bits(nonce, g))
    H = xor(nonce, hash_bits(G, h))
    return G + H

def oaep_unpad(oaep: list[int], g: int, h: int) -> tuple[list[int], list[int]]:
    """
    Algebraic Inversion:
        1. r  = H XOR hash_2(G)
              = (r XOR hash_2(G)) XOR hash_2(G) = r
        2. mm = G XOR hash_1(r)
              = (mm XOR hash_1(r)) XOR hash_1(r) = mm
        3. Check trailing zeros in mm to guarantee CCA2 integrity
    """
    assert len(oaep) == g + h, f"Expected {g + h} bits, got {len(oaep)}"
    G = oaep[:g]
    H = oaep[g:g + h]
    nonce = xor(H, hash_bits(G, h))
    mm = xor(G, hash_bits(nonce, g))
    return mm, nonce

def encrypt_block(message_block: list[int], n: int, public_key: int, nonce: list[int], g: int, h: int) -> list[int]:
    oaep = oaep_pad(message_block, nonce, g, h)
    m_int = bits_to_int(oaep)
    assert m_int < n, f"OAEP block exceeds modulus n"
    c_int = pow(m_int, public_key, n)
    return convert_to_bits(c_int, n.bit_length())

def decrypt_block(ciphertext_block: list[int], n: int, private_key: int, g: int, h: int) -> list[int]:
    c_int = bits_to_int(ciphertext_block)
    m_int = pow(c_int, private_key, n)
    oaep = convert_to_bits(m_int, g + h)
    mm, _ = oaep_unpad(oaep, g, h)
    return mm


# =====================================================================
# 3. MULTI-BLOCK ARBITRARY LENGTH ENCRYPTION & DECRYPTION
# =====================================================================

def encrypt_long_message(plaintext: str, n: int, public_key: int, g: int, h: int) -> list[list[int]]:
    """Splits arbitrary-length message into chunks of size <= g bits and encrypts each."""
    raw_bytes = plaintext.encode('latin-1')
    chunk_byte_size = g // 8  # Maxqimum whole bytes that fit in g bits

    cipher_blocks = []
    for i in range(0, len(raw_bytes), chunk_byte_size):
        chunk = raw_bytes[i:i + chunk_byte_size]
        chunk_bits = []
        for byte in chunk:
            for shift in range(7, -1, -1):
                chunk_bits.append((byte >> shift) & 1)
        
        # Fresh random nonce for every block (IND-CCA2 requirement)
        nonce = [secrets.randbelow(2) for _ in range(h)]
        c_block = encrypt_block(chunk_bits, n, public_key, nonce, g, h)
        cipher_blocks.append(c_block)

    return cipher_blocks

def decrypt_long_message(cipher_blocks: list[list[int]], n: int, private_key: int, g: int, h: int, total_length: int) -> str:
    """Decrypts each block, reassembles bytes, and truncates to original message length."""
    recovered_bytes = bytearray()
    chunk_byte_size = g // 8

    for c_block in cipher_blocks:
        mm_bits = decrypt_block(c_block, n, private_key, g, h)
        block_bytes = bits_to_bytes(mm_bits[:g])
        recovered_bytes.extend(block_bytes[:chunk_byte_size])

    return recovered_bytes[:total_length].decode('latin-1')


# =====================================================================
# 4. RSA KEY GENERATION
# =====================================================================

def is_prime(candidate: int, k: int = 40) -> bool:
    if candidate < 2: return False
    if candidate in (2, 3): return True
    if candidate % 2 == 0: return False
    r, d = 0, candidate - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)
        if x == 1 or x == candidate - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def generate_rsa_keypair(key_bits: int = 1024):
    while True:
        p = generate_prime(key_bits // 2)
        q = generate_prime(key_bits // 2)
        n = p * q
        if n.bit_length() == key_bits and p != q:
            break
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (n, e), (n, d)


# =====================================================================
# 5. EXECUTION PIPELINE
# =====================================================================

if __name__ == "__main__":
    # Long plaintext test (690 bytes / 5520 bits)
    plaintext = "RSA-OAEP test message! " * 30
    #plaintext = "RSA-OAEP test message! " 

    print("==================================================")
    print("1. ORIGINAL INPUT")
    print("==================================================")
    print(f"Plaintext length: {len(plaintext)} characters ({len(plaintext) * 8} bits)")
    print(f"Preview: '{plaintext[:60]}...'")

    print("\nGenerating 1024-bit RSA key pair...")
    (n, public_key), (_, private_key) = generate_rsa_keypair(1024)
    modulus_bits = n.bit_length()

    # Parameters: g + h <= 1023 bits
    h = 256
    # Round g down to a whole byte boundary (95 bytes = 760 bits)
    g = ((modulus_bits - 1 - h) // 8) * 8

    print(f"Modulus bit length: {modulus_bits}")
    print(f"Block capacity (g): {g} bits ({g // 8} bytes) per RSA block")

    # 1. Encrypt across multiple blocks
    cipher_blocks = encrypt_long_message(plaintext, n, public_key, g, h)

    print("\n==================================================")
    print("2. CIPHERTEXT BLOCKS")
    print("==================================================")
    print(f"Total blocks produced: {len(cipher_blocks)}")
    for idx, block in enumerate(cipher_blocks):
        print(f" Block {idx + 1} (Hex): {hex(bits_to_int(block))[:40]}...")

    # 2. Decrypt all blocks and reconstruct
    decrypted_text = decrypt_long_message(cipher_blocks, n, private_key, g, h, total_length=len(plaintext))

    print("\n==================================================")
    print("3. DECRYPTION RESULT")
    print("==================================================")
    print(f"Decrypted Preview: '{decrypted_text[:60]}...'")
    print(f"Full Match: {plaintext == decrypted_text}")
    print("==================================================")