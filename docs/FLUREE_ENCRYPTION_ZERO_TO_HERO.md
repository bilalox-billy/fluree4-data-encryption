# Fluree Encryption — Zero to Hero

> A complete self-study guide for absolute beginners.
> Every concept is explained from scratch. Every code block is a notebook cell you can run yourself.

---

## Table of Contents

1. [Why does encryption exist?](#1-why-does-encryption-exist)
2. [The two types of encryption](#2-the-two-types-of-encryption)
3. [What is a key?](#3-what-is-a-key)
4. [AES-256-GCM — the algorithm Fluree uses](#4-aes-256-gcm--the-algorithm-fluree-uses)
5. [How Fluree stores encrypted data on disk](#5-how-fluree-stores-encrypted-data-on-disk)
6. [The encryption key — generating and validating](#6-the-encryption-key--generating-and-validating)
7. [Connecting Fluree to your key](#7-connecting-fluree-to-your-key)
8. [Writing and reading data — the full lifecycle](#8-writing-and-reading-data--the-full-lifecycle)
9. [Proving encryption is ON — inspecting raw disk files](#9-proving-encryption-is-on--inspecting-raw-disk-files)
10. [What happens with the wrong key](#10-what-happens-with-the-wrong-key)
11. [Client-side encryption — the extra mile](#11-client-side-encryption--the-extra-mile)
12. [Key management best practices](#12-key-management-best-practices)
13. [Security layers — the complete picture](#13-security-layers--the-complete-picture)
14. [Running the full test suite](#14-running-the-full-test-suite)

---

## 1. Why does encryption exist?

Imagine you build a hospital app. You store patient records in Fluree. One day
someone physically takes the hard drive from your server — or downloads a
backup of your cloud storage. Without encryption, they can open the files and
read every patient name, diagnosis, and medication.

**Encryption turns your data into random noise.** Without the secret key,
the files are completely unreadable. Even if someone has the files, they have
nothing useful.

```
Without encryption:
  File on disk → {"@id": "ex:Alice", "ex:diagnosis": "diabetes"}
  Anyone can read this.

With encryption:
  File on disk → 46 4c 55 00 a3 f2 8b 19 c7 44 ...  (random binary noise)
  Useless without the key.
```

---

## 2. The two types of encryption

Before going further, you need to know there are **two completely different
places** where encryption can happen:

### Type A — Encryption at rest (what Fluree does)

This protects data **while it sits on disk** — in files, databases, backups.

```
Your app  ──────────────────────────────────────►  Fluree HTTP API
          (plain JSON, no encryption in transit)         │
                                                         │ encrypts
                                                         ▼
                                                    Disk files
                                                    (binary noise)
```

The server holds the key. It encrypts every write and decrypts every read
automatically. Your app code sees plain data — always.

### Type B — Encryption in transit (TLS/HTTPS)

This protects data **while it travels over the network** — so no one can
intercept the HTTP request.

```
Your app  ──── HTTPS (TLS) ────►  Fluree server  ────►  Disk
          encrypted in transit    decrypts TLS          (may or may not
                                                         encrypt at rest)
```

These two types are **independent**. You can have one without the other, or
both. In this guide we focus on **Type A — encryption at rest**.

---

## 3. What is a key?

A key is just a sequence of random bytes. Think of it as an extremely long
password. The longer and more random it is, the harder it is to guess.

Fluree requires a **32-byte key** (256 bits). That is 32 numbers, each
between 0 and 255.

```python
# Run this in a notebook cell

import secrets

# Generate 32 cryptographically secure random bytes
key_bytes = secrets.token_bytes(32)

print(f"Type    : {type(key_bytes)}")
print(f"Length  : {len(key_bytes)} bytes = {len(key_bytes) * 8} bits")
print(f"As hex  : {key_bytes.hex()}")
print(f"As ints : {list(key_bytes[:8])} ...")  # first 8 numbers
```

**What you will see:**
```
Type    : <class 'bytes'>
Length  : 32 bytes = 256 bits
As hex  : 3a9f14c2b7...
As ints : [58, 159, 20, 194, ...] ...
```

Because we store and transmit this key as text (in env vars, config files),
we encode it as **Base64** — a way to represent bytes using only printable
characters.

```python
# Run this in a notebook cell

import secrets
import base64

key_bytes = secrets.token_bytes(32)

# Encode to Base64 → safe to put in a config file or env var
key_b64 = base64.b64encode(key_bytes).decode()

print(f"Raw bytes length : {len(key_bytes)}")
print(f"Base64 string    : {key_b64}")
print(f"Base64 length    : {len(key_b64)} characters")

# Decode back → always get 32 bytes
decoded = base64.b64decode(key_b64)
print(f"Decoded length   : {len(decoded)} bytes")
print(f"Round-trip OK    : {key_bytes == decoded}")
```

**What you will see:**
```
Raw bytes length : 32
Base64 string    : k3Fp8XsomeLongStringHere==
Base64 length    : 44 characters
Decoded length   : 32 bytes
Round-trip OK    : True
```

> **Rule:** A valid Fluree encryption key is always exactly **32 bytes**,
> stored as a **44-character Base64 string**.

---

## 4. AES-256-GCM — the algorithm Fluree uses

AES-256-GCM has three parts to its name. Let's break each one down.

### AES — Advanced Encryption Standard

AES is the encryption algorithm itself. It takes a block of data and a key
and scrambles the data into unreadable bytes. It is:

- Used by governments, banks, the military, and your browser every day
- Mathematically proven secure — impossible to crack by brute force with
  current computers (it would take longer than the age of the universe)

### 256 — the key size in bits

256 bits = 32 bytes. This is the strongest variant of AES. There are also
AES-128 and AES-192 but Fluree uses 256 for maximum security.

### GCM — Galois/Counter Mode

GCM does two things at once:

1. **Encrypts** the data (confidentiality)
2. **Signs** the result with an authentication tag (integrity)

The authentication tag is a 16-byte checksum that is mathematically tied to
both the key and the ciphertext. If anyone modifies even a single byte of
the stored data — the tag check fails and decryption is rejected. This is
called **authenticated encryption** and it means:

- You cannot read the data without the key (confidentiality)
- You cannot silently tamper with the data (integrity)

```python
# Run this in a notebook cell
# This demonstrates AES-256-GCM using Python's cryptography library
# Install first: pip install cryptography

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# Your 32-byte key
key = secrets.token_bytes(32)

# GCM needs a nonce (number used once) — 12 bytes, random every time
nonce = secrets.token_bytes(12)

# Create an AESGCM cipher with your key
cipher = AESGCM(key)

# Encrypt
plaintext  = b"Hello, secret world!"
ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

print(f"Plaintext  ({len(plaintext):2d} bytes): {plaintext}")
print(f"Ciphertext ({len(ciphertext):2d} bytes): {ciphertext.hex()}")
print(f"Overhead: {len(ciphertext) - len(plaintext)} bytes (that's the 16-byte GCM tag)")

# Decrypt with correct key and nonce → get plaintext back
recovered = cipher.decrypt(nonce, ciphertext, associated_data=None)
print(f"Decrypted              : {recovered}")
print(f"Match                  : {recovered == plaintext}")
```

```python
# Run this in a notebook cell — what happens with a WRONG key?

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets

key_correct = secrets.token_bytes(32)
key_wrong   = secrets.token_bytes(32)   # completely different key
nonce       = secrets.token_bytes(12)

cipher_correct = AESGCM(key_correct)
cipher_wrong   = AESGCM(key_wrong)

ciphertext = cipher_correct.encrypt(nonce, b"Top secret data", None)

try:
    cipher_wrong.decrypt(nonce, ciphertext, None)
    print("Decrypted successfully — THIS SHOULD NEVER HAPPEN")
except InvalidTag:
    print("InvalidTag raised — the wrong key was rejected")
    print("GCM authentication tag did not match → decryption aborted")
    print("No data was returned. This is the correct behaviour.")
```

**Key insight:** With GCM, a wrong key does not return garbage data — it
returns **nothing at all** and raises an error. You cannot even accidentally
read scrambled data.

---

## 5. How Fluree stores encrypted data on disk

Every file Fluree writes starts with a **22-byte header** followed by the
encrypted data:

```
Byte offset   Content               Size      Meaning
─────────────────────────────────────────────────────────────
0–3           Magic bytes           4 bytes   Always "FLU\0" (0x46 0x4C 0x55 0x00)
4             Version               1 byte    Format version (0x01)
5             Algorithm             1 byte    0x01 = AES-256-GCM
6–9           Key ID                4 bytes   Which key was used (for key rotation)
10–21         Nonce                 12 bytes  Random, unique per write
─────────────────────────────────────────────────────────────
22+           Ciphertext            variable  Your actual encrypted data
last 16       Authentication tag    16 bytes  GCM integrity checksum
```

The magic bytes `FLU\0` at the start are your **quick check** — if the first
4 bytes of a Fluree file are `46 4c 55 00`, encryption is on.

```python
# Run this in a notebook cell
# Let's manually build what a Fluree-style encrypted envelope looks like

import struct
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC     = b"FLU\x00"
VERSION   = b"\x01"
ALGORITHM = b"\x01"         # 0x01 = AES-256-GCM
KEY_ID    = struct.pack(">I", 1)   # key ID = 1, big-endian uint32

key   = secrets.token_bytes(32)
nonce = secrets.token_bytes(12)

header = MAGIC + VERSION + ALGORITHM + KEY_ID + nonce
print(f"Header ({len(header)} bytes): {header.hex()}")
print(f"  Magic    : {MAGIC.hex()} → {MAGIC}")
print(f"  Version  : {VERSION.hex()}")
print(f"  Alg      : {ALGORITHM.hex()}")
print(f"  Key ID   : {KEY_ID.hex()}")
print(f"  Nonce    : {nonce.hex()}")

# Encrypt the payload
cipher    = AESGCM(key)
plaintext = b'{"@id": "ex:Alice", "ex:secret": "TOP_SECRET_VALUE_12345"}'
# AAD = Additional Authenticated Data: the header is included in the tag
ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header)

envelope = header + ciphertext
print(f"\nFull envelope ({len(envelope)} bytes):")
print(f"  First 4 bytes : {envelope[:4].hex()} ← magic bytes FLU\\0")
print(f"  Total         : {len(envelope)} bytes")
print(f"  Plaintext was : {len(plaintext)} bytes")
print(f"  Overhead      : {len(envelope) - len(plaintext)} bytes (22 header + 16 tag)")
```

---

## 6. The encryption key — generating and validating

### Generate a key

```python
# Run this in a notebook cell — generate a production-ready key

import secrets
import base64

def generate_fluree_key() -> str:
    """Generate a cryptographically secure AES-256 key for Fluree."""
    key_bytes = secrets.token_bytes(32)             # 32 truly random bytes
    return base64.b64encode(key_bytes).decode()     # base64-encode for config

key = generate_fluree_key()
print(f"Your Fluree encryption key:")
print(f"  {key}")
print(f"\nSave this somewhere safe. If you lose it, you lose your data.")
print(f"Never commit it to Git.")
```

### Validate a key before using it

```python
# Run this in a notebook cell

import base64
import binascii

def validate_fluree_key(b64_key: str) -> None:
    """
    Validate that a string is a proper Fluree AES-256 key.
    Raises ValueError with a clear message if invalid.
    """
    # Must not be empty
    if not b64_key or not b64_key.strip():
        raise ValueError("Key is empty.")

    # Must be valid Base64
    try:
        key_bytes = base64.b64decode(b64_key)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Not valid Base64: {exc}") from exc

    # Must decode to exactly 32 bytes
    if len(key_bytes) != 32:
        raise ValueError(
            f"Key must be 32 bytes (AES-256). "
            f"Got {len(key_bytes)} bytes after Base64 decoding. "
            f"Common mistake: using the raw string instead of base64-encoding it."
        )

    print(f"Key is valid: {len(key_bytes)} bytes = {len(key_bytes) * 8} bits")


# Test with a valid key
import secrets
good_key = base64.b64encode(secrets.token_bytes(32)).decode()
validate_fluree_key(good_key)

# Test with the placeholder from the docker-compose file
print()
try:
    validate_fluree_key("FLUREE_ENCRYPTION_KEY")   # the mistake in docker-compose
except ValueError as e:
    print(f"Invalid key caught: {e}")

# Test with an empty string
print()
try:
    validate_fluree_key("")
except ValueError as e:
    print(f"Empty key caught: {e}")
```

**What you will see:**
```
Key is valid: 32 bytes = 256 bits

Invalid key caught: Not valid Base64: Invalid base64-encoded string

Empty key caught: Key is empty.
```

---

## 7. Connecting Fluree to your key

The key reaches Fluree through an **environment variable** called
`FLUREE_ENCRYPTION_KEY`. This is set before the server starts and the server
reads it once at startup.

### In Docker (local development)

```python
# Run this in a notebook cell
# Shows how to write a .env file and validate it — do this ONCE before docker-compose up

import secrets
import base64
import os

def write_env_file(path: str = ".env") -> str:
    """Generate a key and write it to a .env file."""
    key = base64.b64encode(secrets.token_bytes(32)).decode()

    with open(path, "w") as f:
        f.write(f"FLUREE_ENCRYPTION_KEY={key}\n")

    print(f"Written to {path}")
    print(f"Key (first 8 chars): {key[:8]}...")
    print(f"NEVER commit this file to Git.")
    return key

# Run once
key = write_env_file()

# Then run: docker-compose up -d
# docker-compose.yml reads: FLUREE_ENCRYPTION_KEY: "${FLUREE_ENCRYPTION_KEY}"
```

### Verify the server is using the key

```python
# Run this in a notebook cell — check Fluree is healthy and responding

import requests

def check_fluree_health(url: str = "http://localhost:8090") -> bool:
    try:
        r = requests.get(f"{url}/health", timeout=5)
        print(f"Status code : {r.status_code}")
        print(f"Response    : {r.text[:200]}")
        return r.status_code < 500
    except requests.ConnectionError:
        print("Cannot reach Fluree. Is docker-compose up running?")
        return False

check_fluree_health()
```

---

## 8. Writing and reading data — the full lifecycle

Here is the full journey of a piece of sensitive data through Fluree, step
by step.

### Step 1 — Create a ledger

A **ledger** in Fluree is like a database. You must create it before writing
data. The format is `name:branch` (e.g. `myapp:main`).

```python
# Run this in a notebook cell

import requests

FLUREE = "http://localhost:8090"
LEDGER = "demo:main"

def create_ledger(ledger: str) -> None:
    r = requests.post(f"{FLUREE}/v1/fluree/create", json={"ledger": ledger})
    if r.status_code in (200, 201):
        print(f"Ledger '{ledger}' created.")
    elif r.status_code == 409:
        print(f"Ledger '{ledger}' already exists (that's fine).")
    else:
        raise RuntimeError(f"Create failed: {r.status_code} {r.text}")

create_ledger(LEDGER)
```

### Step 2 — Insert data

Fluree uses **JSON-LD** format. JSON-LD is normal JSON with a `@context`
that gives meaning to your field names by mapping them to full URLs. This
makes the data self-describing and interoperable.

```python
# Run this in a notebook cell

import requests

FLUREE = "http://localhost:8090"
LEDGER = "demo:main"

# @context maps short names to full URIs
# "ex:name" means "http://example.org/ns/name"
# This makes data unambiguous and machine-readable

data = {
    "@context": {"ex": "http://example.org/ns/"},
    "@graph": [
        {
            "@id":       "ex:Alice",          # unique identifier
            "@type":     "ex:Person",          # what kind of thing this is
            "ex:name":   "Alice",
            "ex:secret": "TOP_SECRET_VALUE_12345",
        }
    ],
}

r = requests.post(
    f"{FLUREE}/v1/fluree/insert",
    params={"ledger": LEDGER},          # ledger goes in the URL params
    json=data,                          # JSON-LD body
)

if r.status_code in (200, 201):
    print("Data inserted successfully.")
    print(f"Server response: {r.json()}")
else:
    print(f"Insert failed: {r.status_code} {r.text}")
```

> **What happens inside the server:**
> 1. Fluree receives the JSON-LD
> 2. Converts it to RDF triples (the internal graph format)
> 3. Generates a random 12-byte nonce
> 4. Encrypts the serialised triples with AES-256-GCM
> 5. Writes `FLU\0 + header + ciphertext` to disk
> 6. Returns a commit summary to you

### Step 3 — Query data

```python
# Run this in a notebook cell

import requests

FLUREE = "http://localhost:8090"
LEDGER = "demo:main"

# Query using SPARQL-style pattern matching
# ?s, ?name, ?secret are variables (like SQL's SELECT columns)
query = {
    "@context": {"ex": "http://example.org/ns/"},
    "from":   LEDGER,
    "select": ["?name", "?secret"],
    "where": [
        {"@id": "?s", "@type":     "ex:Person"},
        {"@id": "?s", "ex:name":   "?name"},
        {"@id": "?s", "ex:secret": "?secret"},
    ],
}

r = requests.post(f"{FLUREE}/v1/fluree/query", json=query)

if r.status_code == 200:
    results = r.json()
    print(f"Results ({len(results)} row(s)):")
    for row in results:
        print(f"  {row}")
else:
    print(f"Query failed: {r.status_code} {r.text}")
```

> **What happens inside the server:**
> 1. Fluree reads the encrypted blocks from disk
> 2. Decrypts them with the AES-256-GCM key it holds in memory
> 3. Runs the query against the decrypted data
> 4. Returns the plain result to you
>
> **Your Python code sees only step 4 — plain JSON.** You never touch
> encryption or decryption.

---

## 9. Proving encryption is ON — inspecting raw disk files

Trusting the server is not enough. You need to **verify with your own eyes**
that the files on disk are not readable.

### Check the magic bytes

```python
# Run this in a notebook cell
# Copies a storage file out of Docker and checks its first 4 bytes

import io
import tarfile
import subprocess

CONTAINER  = "fluree"
MAGIC      = b"FLU\x00"      # what the first 4 bytes must be if encrypted

def list_storage_files(container: str) -> list:
    result = subprocess.run(
        ["docker", "exec", container, "find", "/var/lib/fluree", "-type", "f"],
        capture_output=True, text=True,
    )
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]


def read_container_file(container: str, remote_path: str) -> bytes:
    """Use docker cp to get raw file bytes — no text encoding issues."""
    proc = subprocess.run(
        ["docker", "cp", f"{container}:{remote_path}", "-"],
        capture_output=True,
    )
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
        for member in tar.getmembers():
            f = tar.extractfile(member)
            if f:
                return f.read()
    return b""


files = list_storage_files(CONTAINER)
print(f"Files on disk ({len(files)}):")
for path in files:
    print(f"  {path}")
```

```python
# Run this in a notebook cell — check each file for magic bytes and plaintext

NEEDLE = b"TOP_SECRET_VALUE_12345"   # the value we stored

for path in files:
    raw = read_container_file(CONTAINER, path)
    if not raw:
        continue

    first_4    = raw[:4]
    first_32   = " ".join(f"{b:02x}" for b in raw[:32])
    is_magic   = first_4 == MAGIC
    has_plain  = NEEDLE in raw

    print(f"\nFile  : {path}")
    print(f"Size  : {len(raw):,} bytes")
    print(f"First 32 bytes : {first_32}")

    if is_magic and not has_plain:
        print(f"Result: [PASS] First 4 bytes = FLU\\0 → ENCRYPTED  ✓")
    elif has_plain:
        print(f"Result: [FAIL] Plaintext found on disk → ENCRYPTION IS OFF  ✗")
    else:
        print(f"Result: [INFO] Config/metadata file (not a data block)")
```

**What you will see when encryption is ON:**
```
File  : /var/lib/fluree/.fluree/storage/demo/main/commit/abc123.fcv2
Size  : 1,234 bytes
First 32 bytes : 46 4c 55 00 01 01 00 00 00 01 a3 f2 8b 19 c7 44 ...
                 ^  ^  ^  ^
                 F  L  U  \0   ← magic bytes — this file is encrypted
Result: [PASS] First 4 bytes = FLU\0 → ENCRYPTED  ✓
```

**What you will see when encryption is OFF** (the placeholder key mistake):
```
File  : /var/lib/fluree/.fluree/storage/demo/main/commit/abc123.fcv2
Size  : 876 bytes
First 32 bytes : 7b 22 40 69 64 22 3a 22 65 78 3a 41 6c 69 63 65 ...
                 ^
                 { ← that's a JSON brace — data is in PLAINTEXT
Result: [FAIL] Plaintext found on disk → ENCRYPTION IS OFF  ✗
```

---

## 10. What happens with the wrong key

This is the most important test. We start a second Fluree container pointing
at the **same volume** (same disk files) but with a **different key**.

```python
# Run this in a notebook cell — understanding the wrong-key scenario

import secrets
import base64

# The correct key that was used to write data
correct_key = base64.b64encode(b"12345678901234567890123456789012").decode()

# A completely random different key
wrong_key   = base64.b64encode(secrets.token_bytes(32)).decode()

print(f"Correct key : {correct_key}")
print(f"Wrong key   : {wrong_key}")
print(f"Same?       : {correct_key == wrong_key}")

# These two keys will produce completely different encryption results.
# Data encrypted with the correct key CANNOT be decrypted with the wrong key.
# The GCM authentication tag will not match → InvalidTag error.
```

```python
# Run this in a notebook cell
# Demonstrate locally what Fluree does internally with the wrong key

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets

# Server A writes data with key_a
key_a  = secrets.token_bytes(32)
nonce  = secrets.token_bytes(12)
cipher_a = AESGCM(key_a)
ciphertext = cipher_a.encrypt(nonce, b"TOP_SECRET_VALUE_12345", None)
print(f"Data encrypted by server A: {ciphertext[:16].hex()}...")

# Server B tries to read with key_b (a different key)
key_b    = secrets.token_bytes(32)
cipher_b = AESGCM(key_b)

try:
    plaintext = cipher_b.decrypt(nonce, ciphertext, None)
    print(f"Decrypted: {plaintext}")   # this line should never print
except InvalidTag:
    print()
    print("InvalidTag exception raised — correct behaviour!")
    print("The wrong key was rejected. No data was returned.")
    print("This is exactly what Fluree does when started with the wrong key.")
```

### Test it for real against your Docker setup

```python
# Run this in a notebook cell
# WARNING: this stops and restarts Docker containers

import time
import subprocess
import requests
import base64
import secrets

CONTAINER = "fluree"
LEDGER    = "demo:main"
WRONG_KEY = base64.b64encode(secrets.token_bytes(32)).decode()

def stop_container(name):
    subprocess.run(["docker", "stop", name], capture_output=True)
    time.sleep(2)
    print(f"Stopped: {name}")

def start_wrong_key_container(wrong_key):
    subprocess.run([
        "docker", "run", "--rm", "-d",
        "--name", f"{CONTAINER}_wrongkey",
        "-p", "8091:8090",
        "-e", f"FLUREE_ENCRYPTION_KEY={wrong_key}",
        "-v", "fluree4-data-encryption_fluree_data:/var/lib/fluree",
        "fluree/server:latest",
    ], capture_output=True)
    print("Started wrong-key container on port 8091")

def wait_for_server(url, retries=15, delay=2.0):
    for _ in range(retries):
        try:
            r = requests.get(f"{url}/health", timeout=3)
            if r.status_code < 500:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(delay)
    return False

# ---- Run the test ----
stop_container(CONTAINER)
start_wrong_key_container(WRONG_KEY)

wrong_url = "http://localhost:8091"
is_up = wait_for_server(wrong_url)

if not is_up:
    print("[PASS] Wrong-key server refused to start — data is protected.")
else:
    print("Wrong-key server started. Querying...")
    query = {
        "@context": {"ex": "http://example.org/ns/"},
        "from":   LEDGER,
        "select": ["?secret"],
        "where":  [{"@id": "?s", "ex:secret": "?secret"}],
    }
    r = requests.post(f"{wrong_url}/v1/fluree/query", json=query, timeout=10)
    if "TOP_SECRET_VALUE_12345" in r.text:
        print("[FAIL] Plaintext returned with wrong key — encryption is broken!")
    else:
        print(f"[PASS] Wrong key got: {r.status_code} — {r.text[:150]}")

# Cleanup
subprocess.run(["docker", "stop", f"{CONTAINER}_wrongkey"], capture_output=True)
subprocess.run(["docker", "start", CONTAINER], capture_output=True)
print("Original container restored.")
```

---

## 11. Client-side encryption — the extra mile

Fluree's built-in encryption protects the **disk**. But when a legitimate
client queries the API, they always get plaintext — because the server
decrypts before responding.

**Client-side encryption** means you encrypt the values in your Python code
**before** sending them to Fluree. Even if someone queries the API, they
only see ciphertext strings — useless without your client key.

```python
# Run this in a notebook cell
# Install: pip install cryptography

from cryptography.fernet import Fernet

# Generate a client-side encryption key (keep this in your app, not in Fluree)
client_key = Fernet.generate_key()
f = Fernet(client_key)

print(f"Client key: {client_key.decode()}")

# The real sensitive value
real_value = b"TOP_SECRET_VALUE_12345"

# Encrypt before storing in Fluree
encrypted_value = f.encrypt(real_value)
print(f"Stored in Fluree: {encrypted_value.decode()}")
print(f"(This is what anyone querying the API sees)")
```

```python
# Run this in a notebook cell — store the encrypted value in Fluree

import requests

FLUREE = "http://localhost:8090"
LEDGER = "demo:main"

# encrypted_value came from the previous cell
data = {
    "@context": {"ex": "http://example.org/ns/"},
    "@graph": [{
        "@id":       "ex:Bob",
        "@type":     "ex:Person",
        "ex:name":   "Bob",
        "ex:secret": encrypted_value.decode(),   # ciphertext string, not plaintext
    }],
}

r = requests.post(
    f"{FLUREE}/v1/fluree/insert",
    params={"ledger": LEDGER},
    json=data,
)
print(f"Insert status: {r.status_code}")
```

```python
# Run this in a notebook cell — retrieve and decrypt

import requests
from cryptography.fernet import Fernet, InvalidToken

FLUREE = "http://localhost:8090"
LEDGER = "demo:main"

# Query — anyone can run this and get the ciphertext
query = {
    "@context": {"ex": "http://example.org/ns/"},
    "from":   LEDGER,
    "select": ["?secret"],
    "where":  [
        {"@id": "?s", "ex:name": "?n"},
        {"@id": "?s", "ex:secret": "?secret"},
    ],
}
r = requests.post(f"{FLUREE}/v1/fluree/query", json=query)
rows = r.json()

print("What the API returns (ciphertext — anyone can see this):")
for row in rows:
    print(f"  {row}")

print()

# Only someone with client_key can decrypt
f = Fernet(client_key)   # client_key from the previous cell

print("What YOUR app sees after decryption:")
for row in rows:
    raw_cipher = row.get("secret", "")
    if not raw_cipher:
        continue
    try:
        plaintext = f.decrypt(raw_cipher.encode())
        print(f"  Decrypted: {plaintext.decode()}")
    except InvalidToken:
        print(f"  Cannot decrypt (wrong key or not encrypted by us)")
```

```python
# Run this in a notebook cell — what happens if someone uses the wrong client key?

from cryptography.fernet import Fernet, InvalidToken

wrong_client_key = Fernet.generate_key()
f_wrong = Fernet(wrong_client_key)

# encrypted_value from two cells ago
try:
    f_wrong.decrypt(encrypted_value)
    print("Decrypted — THIS SHOULD NOT HAPPEN")
except InvalidToken:
    print("InvalidToken raised — wrong client key rejected")
    print("The ciphertext is useless without the correct client key.")
```

### Comparison: Fluree encryption vs client-side encryption

```
Scenario                              Fluree AES-256    Client-side
──────────────────────────────────────────────────────────────────
Someone steals the disk               Protected ✓       Protected ✓
Someone queries the API legitimately  NOT protected     Protected ✓
Someone has the server key            NOT protected     Protected ✓
Performance overhead                  ~5–15% (AES-NI)  Slightly more
Complexity                            Zero (automatic)  You manage the key
```

Use **both** for maximum protection.

---

## 12. Key management best practices

### Never do this

```python
# Run this in a notebook cell — EXAMPLES OF WHAT NOT TO DO

# BAD 1: hardcoded key in source code
KEY = "FLUREE_ENCRYPTION_KEY"       # placeholder string, not a real key

# BAD 2: key committed to Git
# (any key you type in a .py or .env file that you commit is compromised)

# BAD 3: key printed to logs
import logging
key = "k3Fp8X..."
logging.info(f"Starting server with key {key}")  # exposed in logs!

print("The above are examples of what NOT to do.")
```

### Always do this

```python
# Run this in a notebook cell — the correct pattern

import os
import base64
import secrets

def get_key_from_env(var_name: str = "FLUREE_ENCRYPTION_KEY") -> bytes:
    """
    Read the encryption key from an environment variable.
    Fail loudly and early if it is missing or invalid.
    """
    raw = os.environ.get(var_name)

    if not raw:
        raise EnvironmentError(
            f"Environment variable '{var_name}' is not set.\n"
            f"Generate one with:\n"
            f"  python -c \"import secrets,base64; "
            f"print('FLUREE_ENCRYPTION_KEY='+base64.b64encode(secrets.token_bytes(32)).decode())\""
            f" >> .env"
        )

    try:
        key_bytes = base64.b64decode(raw)
    except Exception as exc:
        raise ValueError(f"'{var_name}' is not valid Base64: {exc}") from exc

    if len(key_bytes) != 32:
        raise ValueError(
            f"'{var_name}' decodes to {len(key_bytes)} bytes. "
            f"Must be exactly 32 bytes (AES-256). "
            f"Common cause: value is not base64-encoded."
        )

    return key_bytes

# Simulate having the env var set
os.environ["FLUREE_ENCRYPTION_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()

try:
    key = get_key_from_env()
    print(f"Key loaded: {len(key)} bytes  ✓")
except (EnvironmentError, ValueError) as e:
    print(f"Error: {e}")
```

### On AWS — fetch from Secrets Manager

```python
# Run this in a notebook cell (requires boto3 and AWS credentials)
# pip install boto3

import boto3

def get_key_from_secrets_manager(secret_name: str, region: str = "us-east-1") -> str:
    """
    Fetch the Fluree encryption key from AWS Secrets Manager.
    Call this at application startup. Never log the result.
    """
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return response["SecretString"]

# In production:
# key_b64 = get_key_from_secrets_manager("fluree/encryption-key")
# os.environ["FLUREE_ENCRYPTION_KEY"] = key_b64
print("In production, call get_key_from_secrets_manager() at startup.")
print("Store your key in AWS Secrets Manager, never in code.")
```

---

## 13. Security layers — the complete picture

Think of your Fluree data as a painting in a museum. You protect it with
multiple independent layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4: Client-side encryption  (optional, maximum security)  │
│                                                                 │
│  You encrypt values in Python before sending to Fluree.         │
│  Even legitimate API responses show only ciphertext.            │
│  Tool: cryptography.fernet.Fernet                               │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: Fluree AES-256-GCM  (server-side, at rest)            │
│                                                                 │
│  Set via FLUREE_ENCRYPTION_KEY environment variable.            │
│  Protects disk files, backups, EBS snapshots.                   │
│  Files start with magic bytes FLU\0 when active.                │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: API authentication  (who can query)                   │
│                                                                 │
│  Set FLUREE_DATA_AUTH_MODE=required in docker-compose.          │
│  Every request needs a Bearer token.                            │
│  Without a token: 401 Unauthorized.                             │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1: Network isolation  (who can reach the server)         │
│                                                                 │
│  AWS: Security Group — block port 8090 from 0.0.0.0/0           │
│  Local: bind to 127.0.0.1:8090, not 0.0.0.0:8090               │
│  Only your app servers should reach Fluree.                     │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Run this in a notebook cell — a summary checklist

checklist = {
    "Port 8090 not exposed to public internet": False,     # set in Security Group / compose
    "FLUREE_ENCRYPTION_KEY is a real 32-byte base64 key": False,
    "Key is stored in .env or Secrets Manager (not Git)": False,
    ".env is in .gitignore": False,
    "EBS encryption enabled (AWS)": False,                # checkbox in AWS console
    "FLUREE_DATA_AUTH_MODE=required (production)": False,  # docker-compose
    "Client-side encryption for most sensitive fields": False,
}

print("Security checklist:")
for item, done in checklist.items():
    status = "✓" if done else "✗ (TODO)"
    print(f"  [{status}] {item}")
```

---

## 14. Running the full test suite

The file `test_encryption.py` in this repository runs all three proofs
automatically:

```python
# Run this in a notebook cell — or just run the script directly

import subprocess

result = subprocess.run(
    ["python", "test_encryption.py"],
    capture_output=True,
    text=True,
)

print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)
```

### What each test proves

| Test | What it proves |
|---|---|
| **Test 1 — Correct key round-trip** | Data can be written and read back normally when the server has the correct key |
| **Test 2 — Raw file inspection** | The physical files on disk contain no plaintext — confirmed by scanning every byte |
| **Test 3 — Wrong key** | A server started with a different key cannot read the data — decryption fails |

### Expected output (encryption ON)

```
============================================================
  TEST 1 – Write & read with correct key
============================================================
[+] Ledger 'test:main' ready.
[+] Inserted ex:Alice with secret value.
[+] Query returned 1 result(s): [{"name": "Alice", "secret": "TOP_SECRET_VALUE_12345"}]
[PASS] Secret value round-trips correctly with the correct key.

============================================================
  TEST 2 – Raw disk files must NOT contain plaintext
============================================================
[+] Found 5 file(s) on disk:
      /var/lib/fluree/.fluree/storage/test/main/commit/abc123.fcv2
      ...

      File : /var/lib/fluree/.fluree/storage/test/main/commit/abc123.fcv2
      Size : 1,234 bytes
      First 32 bytes (hex) : 46 4c 55 00 01 01 00 00 00 01 a3 f2 ...
      Contains plaintext   : no

[PASS] All 5 file(s) are free of plaintext.
       → Data is stored encrypted on disk.

============================================================
  TEST 3 – Restart Fluree with a WRONG key, then query
============================================================
[PASS] Wrong-key server returned error 400: Decryption failed

[Done] All encryption tests finished.
```

---

## Summary — everything in one place

```python
# Run this in a notebook cell — the complete reference

# 1. Generate a key
import secrets, base64
key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()
print(f"Key: {key_b64}")   # put this in .env as FLUREE_ENCRYPTION_KEY

# 2. Validate a key
key_bytes = base64.b64decode(key_b64)
assert len(key_bytes) == 32, "Key must be 32 bytes"

# 3. Health check
import requests
r = requests.get("http://localhost:8090/health")
print(f"Health: {r.status_code}")

# 4. Create a ledger
r = requests.post("http://localhost:8090/v1/fluree/create", json={"ledger": "mydb:main"})
print(f"Create: {r.status_code}")   # 201 = created, 409 = already exists

# 5. Insert data (JSON-LD)
r = requests.post(
    "http://localhost:8090/v1/fluree/insert",
    params={"ledger": "mydb:main"},
    json={
        "@context": {"ex": "http://example.org/ns/"},
        "@graph":   [{"@id": "ex:Alice", "ex:name": "Alice", "ex:age": 30}],
    }
)
print(f"Insert: {r.status_code}")

# 6. Query data
r = requests.post("http://localhost:8090/v1/fluree/query", json={
    "@context": {"ex": "http://example.org/ns/"},
    "from":     "mydb:main",
    "select":   ["?name", "?age"],
    "where":    [{"@id": "?s", "ex:name": "?name"}, {"@id": "?s", "ex:age": "?age"}],
})
print(f"Query: {r.json()}")

# 7. Check a file is encrypted (first 4 bytes must be FLU\0)
import io, tarfile, subprocess
proc = subprocess.run(
    ["docker", "cp", "fluree:/var/lib/fluree/.fluree/config.toml", "-"],
    capture_output=True,
)
with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
    for m in tar.getmembers():
        f = tar.extractfile(m)
        if f:
            raw = f.read()
            encrypted = raw[:4] == b"FLU\x00"
            print(f"File encrypted: {encrypted}  (first 4 bytes: {raw[:4].hex()})")
```

---

> **You are now a Fluree encryption expert.**
>
> You understand:
> - Why encryption exists and what it protects
> - How AES-256-GCM works and why GCM is special
> - The exact byte format of every encrypted Fluree file
> - How to generate, validate, and safely store keys
> - How to prove encryption is on by inspecting raw disk files
> - What happens with a wrong key (InvalidTag, no data returned)
> - The difference between server-side and client-side encryption
> - The four security layers you need in production
>
> Source: [Fluree DB v4.0 Storage Encryption](https://labs.flur.ee/docs/db/security/encryption)
