import hashlib
import socket
import secrets

from cryptography.hazmat.primitives.asymmetric import rsa

HOST = "127.0.0.1"
PORT = 7777

# 2048-bit RSA modulus = 256 bytes
N_LEN = 256


def keygen():
    """
    Generate RSA public/private keys and random fallback value r.

    Returns:
        k  = (n, e)       public key
        sk = ((n, d), k, r) secret key
    """
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    priv_nums = priv_key.private_numbers()

    n = priv_nums.public_numbers.n
    e = priv_nums.public_numbers.e
    d = priv_nums.d

    k = (n, e)
    K = (n, d)

    r = secrets.randbelow(n)

    return k, (K, k, r)


def H(b, x, c):
    """
    H(b, x, c) where b is 0 or 1.
    """
    return hashlib.sha256(
        bytes([b])
        + x.to_bytes(N_LEN, "big")
        + c.to_bytes(N_LEN, "big")
    ).digest()


def encap(k):
    """
    Encapsulate a randomly generated plaintext e.

    Returns:
        c   = RSA ciphertext
        key = H(1, e, c)
    """
    n, exp = k

    e = secrets.randbelow(n)
    c = pow(e, exp, n)

    return c, H(1, e, c)


def decap(sk, c):
    """
    Decapsulate ciphertext c.

    If c is a valid RSA encryption of e, return H(1, e, c).
    Otherwise return H(0, r, c).
    """
    (n, d), (_, exp), r = sk

    if 0 <= c < n:
        e = pow(c, d, n)

        if pow(e, exp, n) == c:
            return H(1, e, c)

    return H(0, r, c)


def recv_exact(conn, size):
    """Receive exactly size bytes."""
    buf = b""

    while len(buf) < size:
        chunk = conn.recv(size - len(buf))

        if not chunk:
            raise ConnectionError(
                "Peer closed the connection early."
            )

        buf += chunk

    return buf

def run_server():
    k, sk = keygen()
    n, e = k

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        conn, addr = server.accept()
        with conn:
            print(f"[SERVER] <- Connection from {addr}")
            # Packet 1: public key
            public_key_packet = (
                n.to_bytes(N_LEN, "big")
                + e.to_bytes(4, "big")
            )
            print("[SERVER] -> Sending public key")
            print(f"[SERVER]    n = {n}\n")
            print(f"[SERVER]    e = {e}")
            print(f"[SERVER]    packet size = {len(public_key_packet)} bytes")
            conn.sendall(public_key_packet)
            # Packet 2: ciphertext
            print("[SERVER] <- Waiting for ciphertext...")
            ciphertext_packet = recv_exact(conn, N_LEN)
            print("[SERVER] <- Received ciphertext")
            print(f"[SERVER]    packet size = {len(ciphertext_packet)} bytes")
            c = int.from_bytes(ciphertext_packet, "big")
            print(f"[SERVER]    c = {c}\n")
            # Decapsulation
            key = decap(sk, c)
            print("[SERVER]    Decapsulated session key:")
            print(f"[SERVER]    {key.hex()}")
            print("[SERVER] Done.")

if __name__ == "__main__":
    run_server()
