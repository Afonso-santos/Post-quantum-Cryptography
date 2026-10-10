# Post-Quantum Cryptography: SimpleKEM

## What is this?
This project (Exercise 2.2) upgrades basic RSA encryption into a highly secure Key Encapsulation Mechanism (KEM). 

In simple terms, it allows two computers to safely agree on a shared password (session key) over the internet, while completely blinding any hacker who tries to tamper with the connection.

## How It Works (In Plain English)
Instead of sending a password directly over the network:

1. **The Server (Alice):** Creates standard RSA keys, plus a secret "backup plan" number.
2. **The Client (Bob):** Generates a random number, locks it with the Server's public key, and sends only the locked box over the internet. He then uses a math blender (SHA-256 Hash) on his number to create his password.
3. **The Server (Alice):** Unlocks the box. Before trusting the number inside, she double-checks the math to see if a hacker messed with the box in transit.
   * **If it's safe:** She puts the number through the exact same math blender as Bob to get the identical password.
   * **If it was tampered with:** She quietly uses her secret "backup plan" number in the blender instead. This creates a fake password. The system doesn't crash or send an error, leaving the hacker with zero clues.

## Project Files
* `receiver.py`: The Server. It waits for a connection, checks the math for tampering, and safely generates the password.
* `sender.py`: The Client. It locks a random number, generates its password, and sends the locked box to the server.

## Setup Instructions
You need Python 3 installed. To keep your computer's files clean, install the required library inside an isolated "virtual environment".

**1. Create and activate the environment:**
```bash
python3 -m venv kem-env

# On Mac/Linux run:
source kem-env/bin/activate

# On Windows run:
kem-env\Scripts\activate
```
2. Install the cryptography tool:

```Bash
pip install cryptography
```
How to Run the Project
Open two separate terminal windows. Make sure your virtual environment (kem-env) is activated in both!

**Terminal 1 (Start the Server):**

```Bash
python receiver.py
```
The server is now waiting on port 7777.

**Terminal 2 (Start the Client):**

```Bash
python sender.py
```
The client will connect and send the box. Look at both terminals: they will successfully generate the exact same session key!

## Test the Hacker Defense!
To see the security in action, you can force the Client to act like a hacker and alter the locked box before sending it.

Run the client with this command:

```Bash
python sender.py --tamper
```
Look at the Server terminal. It will quietly catch the math error and generate a completely different (fake) session key to protect the system.