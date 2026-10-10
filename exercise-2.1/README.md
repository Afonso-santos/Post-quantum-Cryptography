# Post-Quantum Cryptography: RSA-OAEP

## What is this?

This project (Exercise 2.1) upgrades textbook RSA encryption from basic one-way security (OW-CPA) into a scheme with indistinguishability under adaptive chosen-ciphertext attacks (IND-CCA2) using **Optimal Asymmetric Encryption Padding (OAEP)**.

In simple terms, standard RSA is predictable and easy for attackers to manipulate. OAEP acts like a cryptographic "blender" that adds fresh randomness and safety checks to the message before it ever touches RSA, ensuring that attackers cannot read, guess, or tamper with the ciphertexts.

---

## How It Works (In Plain English)

### 1. The Flaw in Basic RSA

Textbook RSA is deterministic ($c = m^e \pmod n$). If you encrypt the word `"YES"` ten times, you get the exact same ciphertext ten times. Furthermore, RSA has a mathematical property called malleability: an attacker can multiply two encrypted numbers together to manipulate the decrypted output without ever knowing the private key.

### 2. The Solution: OAEP (Two-Round Feistel Network)

Before encrypting, OAEP transforms the message through four steps:

1. **Redundancy (Safety Seal):** The message is padded with a series of known zeros at the end.


2. **Fresh Randomness (`nonce`):** A random bit sequence is generated. Even if you encrypt the same text twice, the output will look completely different every time.


3. **The Blender (Feistel Network):** The padded message and the random nonce are mixed together using hash functions (SHA-256) and XOR operations to create blocks $G$ and $H$.


4. **RSA Lock:** The combined block $(G \parallel H)$ is encrypted with the RSA public key.



### 3. Decryption and Tamper Detection

When the receiver decrypts the ciphertext using the private key:

* The receiver inverts the Feistel network to recover both the original message and the random nonce.


* **Integrity Check:** The receiver verifies that the safety zeros are intact. If an attacker modified even a single bit of the ciphertext during transit, the Feistel unmasking destroys the zeros, turning them into garbage.


* When the zeros are damaged, the system immediately rejects the ciphertext, preventing CCA2 attacks.



---

## Project Files

* `OAEP.py`: Complete implementation containing bit conversions, SHA-256 based mask generation (MGF1), OAEP padding/unpadding, RSA key generation, and multi-block encryption/decryption routines.



---

## Setup Instructions

The script uses standard built-in Python libraries (`hashlib`, `secrets`, `math`), so no external third-party packages are required.

1. **Navigate to the exercise folder:**
```bash
cd exercise-2.1

```


2. *(Optional)* If using a virtual environment:
```bash
python3 -m venv oaep-env

# On Mac/Linux run:
source oaep-env/bin/activate

# On Windows run:
oaep-env\Scripts\activate

```



---

## How to Run the Project

Run the script directly from your terminal:

```bash
python OAEP.py

```

The script will:

1. Generate an RSA key pair (1024-bit modulus).
2. Take the sample plaintext and pad it using a random nonce and OAEP.


3. Output the resulting ciphertext blocks in hexadecimal format.
4. Decrypt the blocks, check padding validity, and display the recovered plaintext.



---

## Test the Hacker Defense!

OAEP is designed to fail predictably when tampered with. To observe this defense in action, you can flip bits in the ciphertext before decrypting:

```python
# Simulate an attacker flipping a single bit in the ciphertext
tampered_ciphertext = cipher_blocks[0].copy()
tampered_ciphertext[0] ^= 1  # Flip the first bit

# Attempt to decrypt the tampered block
try:
    decrypt_block(tampered_ciphertext, n, private_key, g, h)
except ValueError as e:
    print("Hacker Attack Detected! Ciphertext rejected.")

```

Because of the Feistel diffusion, altering one bit of the ciphertext causes the decrypted padding bits to randomize. The integrity check detects that the trailing zeros are missing and rejects the message, blocking adaptive chosen-ciphertext attacks (IND-CCA2).