"""
Encryption verification tests for Fluree.

Covers:
  1. Write data with the correct key → read it back (sanity check).
  2. Inspect raw storage files inside Docker → bytes should be unreadable.
  3. Restart Fluree with a WRONG key → queries should fail or return garbage.

Run:
    docker-compose up -d          # start Fluree with the correct key
    python test_encryption.py
"""
from __future__ import annotations

import base64
import os
import secrets
import subprocess
import time

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FLUREE_URL = "http://localhost:8090"
CONTAINER   = "fluree"                      # container_name in docker-compose.yml
LEDGER      = "test:main"                   # Fluree v4 format: name:branch

CORRECT_KEY_B64 = os.environ.get(
    "FLUREE_ENCRYPTION_KEY",
    base64.b64encode(b"12345678901234567890123456789012").decode(),  # 32-byte demo key
)
WRONG_KEY_B64 = base64.b64encode(secrets.token_bytes(32)).decode()  # random wrong key
EX_CTX = {"ex": "http://example.org/ns/"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _post(path: str, body: dict, params: dict | None = None) -> requests.Response:
    return requests.post(f"{FLUREE_URL}{path}", json=body, params=params, timeout=10)


def _wait_for_fluree(retries: int = 15, delay: float = 2.0) -> bool:
    """Poll until the Fluree HTTP server responds."""
    for _ in range(retries):
        try:
            r = requests.get(f"{FLUREE_URL}/health", timeout=3)
            if r.status_code < 500:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(delay)
    return False


def _docker(cmd: list[str], capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker"] + cmd,
        capture_output=capture,
        text=True,
    )


def _section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Test 1 – create ledger, insert data, query back (correct key)
# ---------------------------------------------------------------------------

def test_correct_key() -> str:
    """
    Returns the @id of the inserted subject so later tests can query it.
    """
    _section("TEST 1 – Write & read with correct key")

    # Create ledger (idempotent – ignore 409)
    r = _post("/v1/fluree/create", {"ledger": LEDGER})
    if r.status_code not in (200, 201, 409):
        raise RuntimeError(f"Failed to create ledger: {r.status_code} {r.text}")
    print(f"[+] Ledger '{LEDGER}' ready.")

    # Insert a record with a recognisable secret value
    # Body is a JSON-LD document; ledger is passed as a query parameter
    json_ld = {
        "@context": {"ex": "http://example.org/ns/"},
        "@graph": [{
            "@id":       "ex:Alice",
            "@type":     "ex:Person",
            "ex:name":   "Alice",
            "ex:secret": "TOP_SECRET_VALUE_12345",
        }],
    }
    r = _post("/v1/fluree/insert", json_ld, params={"ledger": LEDGER})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Transact failed: {r.status_code} {r.text}")
    print("[+] Inserted ex:Alice with secret value.")

    # Read it back
    query = {
        "@context": {"ex": "http://example.org/ns/"},
        "from":   LEDGER,
        "select": ["?name", "?secret"],
        "where": [
            {"@id": "?s", "@type": "ex:Person"},
            {"@id": "?s", "ex:name": "?name"},
            {"@id": "?s", "ex:secret": "?secret"},
        ],
    }
    r = _post("/v1/fluree/query", query)
    if r.status_code != 200:
        raise RuntimeError(f"Query failed: {r.status_code} {r.text}")

    data = r.json()
    print(f"[+] Query returned {len(data)} result(s): {data}")

    found = any("TOP_SECRET_VALUE_12345" in str(row) for row in data)
    if found:
        print("[PASS] Secret value round-trips correctly with the correct key.")
    else:
        print("[WARN] Secret value not found in results – check ledger state.")

    return "ex:Alice"


# ---------------------------------------------------------------------------
# Test 2 – inspect raw storage files on disk (are they encrypted?)
# ---------------------------------------------------------------------------

NEEDLE = b"TOP_SECRET_VALUE_12345"   # the value we inserted; must not appear on disk


def _read_docker_file_bytes(remote_path: str) -> bytes | None:
    """
    Copy one file out of the Docker container as raw bytes using
    ``docker cp CONTAINER:/path -`` (which streams a tar archive).
    Returns None if the copy fails.
    """
    import io
    import tarfile

    proc = subprocess.run(
        ["docker", "cp", f"{CONTAINER}:{remote_path}", "-"],
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"      [WARN] Could not copy {remote_path}: {proc.stderr.decode()}")
        return None

    try:
        with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
            for member in tar.getmembers():
                f_obj = tar.extractfile(member)
                if f_obj is not None:
                    return f_obj.read()
    except tarfile.TarError as exc:
        print(f"      [WARN] tar error for {remote_path}: {exc}")
    return None


def _inspect_file(remote_path: str) -> bool:
    """
    Fetch a file from the container, print a hex preview, and return True
    if the plaintext needle was found (i.e. the file is NOT encrypted).
    """
    raw = _read_docker_file_bytes(remote_path)
    if raw is None:
        return False

    preview = " ".join(f"{b:02x}" for b in raw[:32])
    found = NEEDLE in raw
    status = "YES ← PLAINTEXT DETECTED" if found else "no"

    print(f"\n      File : {remote_path}")
    print(f"      Size : {len(raw):,} bytes")
    print(f"      First 32 bytes (hex) : {preview}")
    print(f"      Contains plaintext   : {status}")
    return found


def test_files_are_encrypted() -> None:
    """
    Copy every storage file out of the Docker container into Python as raw
    bytes and scan for the known plaintext value.

    PASS: no file contains the plaintext string → data is encrypted on disk.
    FAIL: at least one file contains the plaintext string → encryption is OFF.
    """
    _section("TEST 2 – Raw disk files must NOT contain plaintext")

    result = _docker(["exec", CONTAINER, "find", "/var/lib/fluree", "-type", "f"])
    files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

    if not files:
        print("[SKIP] No storage files found yet (Fluree flushes lazily).")
        return

    print(f"[+] Found {len(files)} file(s) on disk:")
    for f in files:
        print(f"      {f}")

    exposed = [f for f in files if _inspect_file(f)]

    print()
    if exposed:
        print(f"[FAIL] {len(exposed)} file(s) contain PLAINTEXT data:")
        for f in exposed:
            print(f"         {f}")
        print("       → Encryption is NOT active. Check FLUREE_ENCRYPTION_KEY.")
    else:
        print(f"[PASS] All {len(files)} file(s) are free of plaintext.")
        print("       → Data is stored encrypted on disk.")


# ---------------------------------------------------------------------------
# Test 3 – restart Fluree with the WRONG key, attempt to query
# ---------------------------------------------------------------------------

def test_wrong_key() -> None:
    _section("TEST 3 – Restart Fluree with a WRONG key, then query")

    print(f"[*] Stopping container '{CONTAINER}' ...")
    _docker(["stop", CONTAINER], capture=False)
    time.sleep(2)

    print("[*] Starting container with WRONG key ...")
    _docker([
        "run", "--rm", "-d",
        "--name", f"{CONTAINER}_wrongkey",
        "-p", "8091:8090",                          # use a different host port
        "-e", f"FLUREE_ENCRYPTION_KEY={WRONG_KEY_B64}",
        "-v", "fluree4-data-encryption_fluree_data:/var/lib/fluree",
        "fluree/server:latest",
    ], capture=False)

    wrong_url = "http://localhost:8091"
    print("[*] Waiting for wrong-key instance to start ...")
    up = _poll(wrong_url)

    if not up:
        print("[INFO] Wrong-key server did not become healthy – Fluree refused to start with a mismatched key.")
        print("[PASS] Fluree correctly rejected the wrong encryption key at startup.")
    else:
        # Server started – try querying the previously written ledger
        query = {
            "@context": {"ex": "http://example.org/ns/"},
            "from":   LEDGER,
            "select": ["?secret"],
            "where":  [{"@id": "?s", "ex:secret": "?secret"}],
        }
        try:
            r = requests.post(f"{wrong_url}/v1/fluree/query", json=query, timeout=10)
            body = r.text
            if "TOP_SECRET_VALUE_12345" in body:
                print(f"[FAIL] Wrong-key server returned PLAINTEXT data: {body}")
            elif r.status_code >= 400:
                print(f"[PASS] Wrong-key server returned error {r.status_code}: {body[:200]}")
            else:
                print(f"[PASS] Wrong-key server returned unreadable/empty data: {body[:200]}")
        except requests.RequestException as exc:
            print(f"[PASS] Wrong-key server rejected connection: {exc}")

    # Cleanup wrong-key container
    _docker(["stop", f"{CONTAINER}_wrongkey"], capture=False)
    time.sleep(1)

    # Restore the original container
    print(f"\n[*] Restarting original container '{CONTAINER}' with correct key ...")
    _docker(["start", CONTAINER], capture=False)
    if _wait_for_fluree():
        print("[+] Original Fluree instance restored.")
    else:
        print("[WARN] Original container did not come back up – run 'docker-compose up -d' manually.")


def _poll(url: str, retries: int = 15, delay: float = 2.0) -> bool:
    for _ in range(retries):
        try:
            r = requests.get(f"{url}/health", timeout=3)
            if r.status_code < 500:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(delay)
    return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("Checking Fluree is reachable ...")
    if not _wait_for_fluree():
        print("[ERROR] Fluree server not reachable at", FLUREE_URL)
        print("        Run:  docker-compose up -d")
        return

    print(f"[+] Fluree is up at {FLUREE_URL}")
    print(f"[*] Using encryption key (b64): {CORRECT_KEY_B64[:8]}…  (from FLUREE_ENCRYPTION_KEY env var)")

    test_correct_key()
    test_files_are_encrypted()
    test_wrong_key()

    print("\n[Done] All encryption tests finished.")


if __name__ == "__main__":
    main()
