# Fluree Encryption — Complete Beginner's Guide

> Based on [Fluree DB v4.0 Storage Encryption docs](https://labs.flur.ee/docs/db/security/encryption)
> and the test suite in `test_encryption.py`.

---

## 1. What problem does encryption solve?

Imagine you store sensitive records in Fluree and someone steals the hard drive
(or an AWS EBS snapshot, or a backup file). Without encryption they can open
the files and read everything. With encryption the files look like random
garbage — completely unreadable without the key.

```
WITHOUT encryption            WITH encryption
─────────────────────         ────────────────────────────────────
"ex:secret": "1234"   →  disk  →  46 4c 55 00 01 01 a3 f2 ...
                                   (AES-256-GCM ciphertext)
```

---

## 2. The golden rule: encryption is SERVER-SIDE and transparent

```
Your Python code              Fluree Server                   Disk
──────────────────            ─────────────────────────────   ──────────────
POST /v1/fluree/insert   →    encrypt with AES-256 key    →  [binary blob]
POST /v1/fluree/query    ←    decrypt with AES-256 key    ←  [binary blob]
```

- Your Python code **never sees the key** and **never handles raw bytes**.
- You always send and receive plain readable JSON.
- The server silently encrypts every write and decrypts every read.

---

## 3. The algorithm: AES-256-GCM

Fluree uses **AES-256-GCM** — the industry gold standard for encryption.
Breaking it down:

| Part | Meaning |
|---|---|
| **AES** | Advanced Encryption Standard — the cipher used by banks and governments |
| **256** | Key size in bits (= 32 bytes). Larger = harder to crack |
| **GCM** | Galois/Counter Mode — also detects if someone tampered with the data |

The key must be **exactly 32 bytes**, Base64-encoded for storage.

```python
import secrets, base64

# Generate a cryptographically secure 32-byte key
key_bytes = secrets.token_bytes(32)                    # 32 random bytes
key_b64   = base64.b64encode(key_bytes).decode()       # e.g. "k3Fp8X...=="

print(f"Key bytes : {len(key_bytes)} bytes")           # always 32
print(f"Key b64   : {key_b64}")                        # 44 characters
```

---

## 4. What each file on disk looks like

Every encrypted file Fluree writes starts with a 22-byte header called the
**envelope**:

```
┌──────────────────────────────────────────────────────────────┐
│ Header (22 bytes)                                            │
├──────────┬─────────┬─────────┬──────────┬───────────────────┤
│ Magic    │ Version │ Alg     │ Key ID   │ Nonce             │
│ 4 bytes  │ 1 byte  │ 1 byte  │ 4 bytes  │ 12 bytes          │
│ "FLU\0"  │ 0x01    │ 0x01    │ uint32   │ random            │
├──────────┴─────────┴─────────┴──────────┴───────────────────┤
│ Ciphertext (variable length)                                 │
├──────────────────────────────────────────────────────────────┤
│ Authentication Tag (16 bytes)                                │
└──────────────────────────────────────────────────────────────┘
```

- **Magic bytes** `FLU\0` let Fluree instantly detect whether a file is
  encrypted or not.
- **Nonce** is a random 12-byte number generated fresh for *every single
  write*, so encrypting the same data twice produces completely different
  ciphertext.
- **Authentication Tag** detects tampering — if someone flips even one bit on
  disk, decryption fails loudly.

### Check the magic bytes yourself

```python
import io, tarfile, subprocess

def read_file_from_container(container: str, remote_path: str) -> bytes:
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

raw = read_file_from_container("fluree", "/var/lib/fluree/.fluree/storage/test/main/commit/somefile.fcv2")

magic = raw[:4]
print(f"Magic bytes : {magic!r}")
# Encrypted  → b'FLU\x00'
# Plaintext  → b'{' or other JSON/Avro bytes
```

---

## 5. Setting up the key (three ways)

### Way 1 — Direct 32-byte key (testing only)

```python
import secrets

key: bytes = secrets.token_bytes(32)   # random 32 bytes
# Pass to FlureeBuilder.build_encrypted(key) in the Rust API
# In Python: just use this key to start the server with the env var approach
```

### Way 2 — Base64-encoded string

```python
import base64, secrets

key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()
# → "k3Fp8X...==" (44 characters)

# Validate it decodes to exactly 32 bytes
decoded = base64.b64decode(key_b64)
assert len(decoded) == 32, f"Key must be 32 bytes, got {len(decoded)}"
```

### Way 3 — From an environment variable (recommended for production)

```python
import os, base64

raw = os.environ.get("FLUREE_ENCRYPTION_KEY")
if not raw:
    raise EnvironmentError("FLUREE_ENCRYPTION_KEY is not set!")

key = base64.b64decode(raw)
assert len(key) == 32, f"Key must decode to 32 bytes, got {len(key)}"
```

In `docker-compose.yml`:

```yaml
environment:
  FLUREE_ENCRYPTION_KEY: "${FLUREE_ENCRYPTION_KEY}"   # read from .env file
```

In `.env` (never commit this file):

```
FLUREE_ENCRYPTION_KEY=k3Fp8XsomeLongBase64StringHere==
```

---

## 6. What happens with the WRONG key

When Fluree starts with a **different key** than the one used to write the
data, it cannot authenticate the GCM tag. You will see errors like:

```
"Decryption failed"
"Unknown encryption key ID"
"Invalid encryption format"
```

This is the correct and expected behaviour — it proves the data is protected.

```python
import requests

# Server started with wrong key — query the previously written ledger
r = requests.post("http://localhost:8091/v1/fluree/query", json={
    "@context": {"ex": "http://example.org/ns/"},
    "from":   "test:main",
    "select": ["?secret"],
    "where":  [{"@id": "?s", "ex:secret": "?secret"}],
}, timeout=10)

print(r.status_code)   # 400 or 500 — decryption error
print(r.text)          # "Decryption failed" or similar
```

---

## 7. Verifying encryption is actually ON

This is exactly what `test_encryption.py` does. Here is the core idea as a
standalone snippet:

```python
import io, tarfile, subprocess

NEEDLE    = b"TOP_SECRET_VALUE_12345"   # the value we stored
CONTAINER = "fluree"

# 1. list all files Fluree wrote
result = subprocess.run(
    ["docker", "exec", CONTAINER, "find", "/var/lib/fluree", "-type", "f"],
    capture_output=True, text=True,
)
files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

# 2. copy each file out as raw bytes and scan for the plaintext needle
for path in files:
    proc = subprocess.run(
        ["docker", "cp", f"{CONTAINER}:{path}", "-"],
        capture_output=True,
    )
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
        for member in tar.getmembers():
            f = tar.extractfile(member)
            if not f:
                continue
            raw = f.read()
            first_32 = " ".join(f"{b:02x}" for b in raw[:32])

            if NEEDLE in raw:
                print(f"[FAIL] {path}")
                print(f"       Plaintext found on disk → encryption is OFF")
            else:
                print(f"[PASS] {path}")
                print(f"       First 32 bytes: {first_32}")
                # If encrypted, first 4 bytes will be: 46 4c 55 00  (FLU\0)
```

**PASS output** (encryption ON):
```
[PASS] /var/lib/fluree/.fluree/storage/test/main/commit/abc123.fcv2
       First 32 bytes: 46 4c 55 00 01 01 00 00 00 01 a3 f2 8b ...
                       ^  ^  ^  ^
                       F  L  U  \0  ← magic bytes prove it's encrypted
```

**FAIL output** (encryption OFF):
```
[FAIL] /var/lib/fluree/.fluree/storage/test/main/commit/abc123.fcv2
       Plaintext found on disk → encryption is OFF
```

---

## 8. The full security stack

Disk encryption alone is not enough. Think of it as layers of protection:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4 (optional): Client-side encryption                 │
│  You encrypt values in Python before sending to Fluree.     │
│  Protects data even from the database server itself.        │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Fluree AES-256-GCM  ← FLUREE_ENCRYPTION_KEY      │
│  Protects stolen disk / EBS snapshots / backups.            │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: API authentication  ← Bearer tokens               │
│  Protects against unauthorised HTTP queries.                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Network / firewall  ← VPC / Security Group        │
│  Protects port 8090 from the public internet.               │
└─────────────────────────────────────────────────────────────┘
```

### Optional: client-side encryption with Python

```python
from cryptography.fernet import Fernet, InvalidToken

# Generate key once and store it safely
key = Fernet.generate_key()             # 32-byte URL-safe base64 key
f   = Fernet(key)

# Encrypt before storing in Fluree
plaintext  = b"TOP_SECRET_VALUE_12345"
ciphertext = f.encrypt(plaintext)       # random each time

# Store the ciphertext string in Fluree
import requests
requests.post("http://localhost:8090/v1/fluree/insert",
    params={"ledger": "test:main"},
    json={
        "@context": {"ex": "http://example.org/ns/"},
        "@graph": [{"@id": "ex:Alice", "ex:secret": ciphertext.decode()}],
    }
)

# Decrypt after reading from Fluree
# --- query returns ciphertext ---
ciphertext_from_db = b"..."             # value returned by /v1/fluree/query
try:
    plaintext = f.decrypt(ciphertext_from_db)
    print(plaintext.decode())           # "TOP_SECRET_VALUE_12345"
except InvalidToken:
    print("Wrong key or tampered data")
```

With this approach, even if someone queries the API directly, they only see
the ciphertext — not the original value.

---

## 9. Key management on AWS

Never hardcode or commit the key. On AWS:

```python
import boto3

def get_fluree_key() -> str:
    """Fetch the encryption key from AWS Secrets Manager at startup."""
    client = boto3.client("secretsmanager", region_name="us-east-1")
    secret = client.get_secret_value(SecretId="fluree/encryption-key")
    return secret["SecretString"]   # the base64 key string

key_b64 = get_fluree_key()
# Inject into the process env before starting / configuring Fluree
import os
os.environ["FLUREE_ENCRYPTION_KEY"] = key_b64
```

Stack on AWS:

| What | AWS service | Protects against |
|---|---|---|
| Disk encryption | EBS with KMS | Physical drive theft |
| Fluree AES-256 | `FLUREE_ENCRYPTION_KEY` in Secrets Manager | Compromised EBS snapshot |
| API access | Fluree Bearer tokens | Unauthorised HTTP queries |
| Network access | VPC Security Group (block 0.0.0.0/0 on 8090) | Public internet access |

---

## 10. Quick reference cheatsheet

```python
import secrets, base64, os

# Generate a key
key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()

# Validate a key from env
raw  = os.environ["FLUREE_ENCRYPTION_KEY"]
key  = base64.b64decode(raw)
assert len(key) == 32

# Create a ledger
import requests
requests.post("http://localhost:8090/v1/fluree/create",
              json={"ledger": "mydb:main"})

# Insert data (JSON-LD)
requests.post("http://localhost:8090/v1/fluree/insert",
    params={"ledger": "mydb:main"},
    json={
        "@context": {"ex": "http://example.org/ns/"},
        "@graph":   [{"@id": "ex:Alice", "ex:name": "Alice"}],
    }
)

# Query data
r = requests.post("http://localhost:8090/v1/fluree/query", json={
    "@context": {"ex": "http://example.org/ns/"},
    "from":     "mydb:main",
    "select":   ["?name"],
    "where":    [{"@id": "?s", "ex:name": "?name"}],
})
print(r.json())   # [{"name": "Alice"}]

# Check if a disk file is encrypted (first 4 bytes must be FLU\0)
FLUREE_MAGIC = b"FLU\x00"
# encrypted  → raw[:4] == FLUREE_MAGIC   ✓
# plaintext  → raw[:4] != FLUREE_MAGIC   ✗
```

---

## Summary

| Concept | One sentence |
|---|---|
| AES-256-GCM | The cipher Fluree uses — 32-byte key, authenticated, tamper-proof |
| FLUREE_ENCRYPTION_KEY | Base64-encoded 32-byte env var the server reads at startup |
| Transparent encryption | Server encrypts writes and decrypts reads — client never sees it |
| Magic bytes `FLU\0` | First 4 bytes of every encrypted file — how you verify it's on |
| Wrong key | GCM tag verification fails → decryption error, no data returned |
| Client-side encryption | Optional extra layer: you encrypt values before storing |
| AWS best practice | Store key in Secrets Manager, enable EBS encryption, close port 8090 |
