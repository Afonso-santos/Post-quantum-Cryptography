import hashlib
import socket
import sys
import secrets

HOST = "127.0.0.1"
PORT = 7777

# 2048-bit RSA modulus = 256 bytes
N_LEN = 256
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
    Generate a random plaintext e, encrypt it using RSA,
    and derive the session key.
    """
    n, exp = k

    e = secrets.randbelow(n)
    c = pow(e, exp, n)

    return c, H(1, e, c)

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

def run_client(tamper=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

        try:
            print(f"[CLIENT] -> Connecting to {HOST}:{PORT}")
            client.connect((HOST, PORT))

        except ConnectionRefusedError:
            print(
                "[CLIENT] Error: Could not connect to the server. "
                "Is the server running?"
            )
            return

        # Packet 1: public key
        print("[CLIENT] <- Waiting for public key...")

        raw = recv_exact(client, N_LEN + 4)

        print("[CLIENT] <- Received public key")
        print(f"[CLIENT]    packet size = {len(raw)} bytes")

        n = int.from_bytes(
            raw[:N_LEN],
            "big"
        )

        e = int.from_bytes(
            raw[N_LEN:],
            "big"
        )

        print(f"[CLIENT]    n = {n}")
        print(f"[CLIENT]    e = {e}")

        k = (n, e)
        # Encapsulation
        c, key = encap(k)
        print("[CLIENT]    Generated ciphertext")
        print(f"[CLIENT]    c = {c}")

        # Optional tampering
        if tamper:
            print("[CLIENT] !!! TAMPERING WITH CIPHERTEXT !!!")
            c ^= 1

        # Packet 2: ciphertext
        ciphertext_packet = c.to_bytes(N_LEN, "big")

        print("[CLIENT] -> Sending ciphertext")
        print(
            f"[CLIENT]    packet size = "
            f"{len(ciphertext_packet)} bytes"
        )

        client.sendall(ciphertext_packet)

        # Client's expected key
        print("[CLIENT]    Session key:")
        print(f"[CLIENT]    {key.hex()}")

        print("[CLIENT] Done.")


if __name__ == "__main__":
    run_client(
        tamper="--tamper" in sys.argv
    )
