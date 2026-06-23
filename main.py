"""
Python equivalent of the Rust fluree_db_api encryption examples.

Because Python has no embedded Fluree library, the builder configures
a connection to a running Fluree HTTP server and carries the encryption
key for reference / validation.  Actual AES-256 encryption is enforced
server-side via the Fluree server configuration.
"""

import base64
import os
import secrets
from typing import Optional

import requests

_DEFAULT_URL = "http://localhost:8090"
_DEFAULT_PATH = "/data/fluree"
_K_GRAPH = "@graph"
_K_TYPE = "@type"


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

class FlureeConnection:
    """Live connection to a Fluree server."""

    def __init__(self, base_url: str = _DEFAULT_URL):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()

    def query(self, ledger: str, query: dict) -> dict:
        """
        Execute a JSON-LD query.  ``query`` is merged with ``{"from": ledger}``.
        Example:
            conn.query("mydb:main", {"select": ["?name"], "where": [{"@id": "?s", "ex:name": "?name"}]})
        """
        resp = self._session.post(
            f"{self.base_url}/v1/fluree/query",
            json={"from": ledger, **query},
        )
        resp.raise_for_status()
        return resp.json()

    def insert(self, ledger: str, json_ld: dict) -> dict:
        """
        Insert JSON-LD data into a ledger (fails if triples already exist).
        ``json_ld`` must be a JSON-LD document, e.g.::

            {"@context": {"ex": "http://example.org/ns/"},
             "@graph": [{"@id": "ex:alice", "ex:name": "Alice"}]}
        """
        resp = self._session.post(
            f"{self.base_url}/v1/fluree/insert",
            params={"ledger": ledger},
            json=json_ld,
        )
        resp.raise_for_status()
        return resp.json()

    def upsert(self, ledger: str, json_ld: dict) -> dict:
        """Like ``insert`` but overwrites existing (subject, predicate) pairs."""
        resp = self._session.post(
            f"{self.base_url}/v1/fluree/upsert",
            params={"ledger": ledger},
            json=json_ld,
        )
        resp.raise_for_status()
        return resp.json()

    def __repr__(self) -> str:
        return f"FlureeConnection(base_url={self.base_url!r})"


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class FlureeBuilder:
    """
    Fluent builder that mirrors the Rust FlureeBuilder API.

    Three encryption options
    ------------------------
    Option 1 – direct raw key (32 bytes):
        FlureeBuilder.file("/data/fluree").build_encrypted(key)

    Option 2 – Base64-encoded key:
        FlureeBuilder.file("/data/fluree")
            .with_encryption_key_base64("your-base64-key")
            .build_encrypted_from_config()

    Option 3 – JSON-LD config with env var:
        FlureeBuilder.from_json_ld(config).build_encrypted_from_config()
    """

    def __init__(self, base_url: str = _DEFAULT_URL):
        self._base_url = base_url
        self._encryption_key: Optional[bytes] = None
        self._config: Optional[dict] = None

    # ------------------------------------------------------------------
    # Factory constructors
    # ------------------------------------------------------------------

    @classmethod
    def file(cls, path: str, base_url: str = _DEFAULT_URL) -> "FlureeBuilder":
        """Create a builder targeting a file-backed storage path."""
        builder = cls(base_url)
        builder._config = {
            "@context": {"@vocab": "https://ns.flur.ee/system#"},
            _K_GRAPH: [{
                _K_TYPE: "Connection",
                "indexStorage": {
                    _K_TYPE: "Storage",
                    "filePath": path,
                },
            }],
        }
        return builder

    @classmethod
    def from_json_ld(
        cls, config: dict, base_url: str = _DEFAULT_URL
    ) -> "FlureeBuilder":
        """Create a builder from a full JSON-LD configuration dict."""
        builder = cls(base_url)
        builder._config = config
        return builder

    # ------------------------------------------------------------------
    # Option 1 – direct raw 32-byte key
    # ------------------------------------------------------------------

    def build_encrypted(self, key: bytes) -> FlureeConnection:
        """Build a connection using a raw 32-byte AES-256 key."""
        if len(key) != 32:
            raise ValueError(
                f"Encryption key must be exactly 32 bytes (AES-256); got {len(key)}."
            )
        self._encryption_key = key
        return self._connect()

    # ------------------------------------------------------------------
    # Option 2 – Base64-encoded key
    # ------------------------------------------------------------------

    def with_encryption_key_base64(self, b64_key: str) -> "FlureeBuilder":
        """Decode and store an AES-256 key from a Base64 string."""
        try:
            key = base64.b64decode(b64_key)
        except Exception as exc:
            raise ValueError(f"Invalid Base64 key: {exc}") from exc

        if len(key) != 32:
            raise ValueError(
                f"Decoded key must be exactly 32 bytes (AES-256); got {len(key)}."
            )
        self._encryption_key = key
        return self

    # ------------------------------------------------------------------
    # Option 3 / shared finaliser
    # ------------------------------------------------------------------

    def build_encrypted_from_config(self) -> FlureeConnection:
        """
        Build using encryption settings already embedded in the JSON-LD
        config (e.g. ``{"envVar": "FLUREE_ENCRYPTION_KEY"}``).

        When the config references an env var, this method resolves it
        locally so the key can be validated before handing off to the
        server.
        """
        self._resolve_env_var_keys()
        return self._connect()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_env_var_keys(self) -> None:
        """Walk the config and resolve any ``{"envVar": "..."}`` references."""
        if self._config is None:
            return

        for graph_node in self._config.get(_K_GRAPH, []):
            storage = graph_node.get("indexStorage", {})
            aes_entry = storage.get("AES256Key")
            if isinstance(aes_entry, dict) and "envVar" in aes_entry:
                var_name = aes_entry["envVar"]
                raw = os.environ.get(var_name)
                if raw is None:
                    raise EnvironmentError(
                        f"Env var '{var_name}' is not set. "
                        "Export it before calling build_encrypted_from_config()."
                    )
                try:
                    key = base64.b64decode(raw)
                except Exception:
                    key = raw.encode()

                if len(key) != 32:
                    raise ValueError(
                        f"Key from env var '{var_name}' must decode to exactly 32 bytes; "
                        f"got {len(key)}."
                    )
                self._encryption_key = key

    def _connect(self) -> FlureeConnection:
        return FlureeConnection(self._base_url)


# ---------------------------------------------------------------------------
# Demo / smoke test
# ---------------------------------------------------------------------------

def main() -> None:
    # --- Option 1: direct raw 32-byte key ---
    key: bytes = secrets.token_bytes(32)
    fluree = FlureeBuilder.file(_DEFAULT_PATH).build_encrypted(key)
    print("Option 1 –", fluree)

    # --- Option 2: Base64-encoded key ---
    b64_key: str = base64.b64encode(key).decode()
    fluree = (
        FlureeBuilder.file(_DEFAULT_PATH)
        .with_encryption_key_base64(b64_key)
        .build_encrypted_from_config()
    )
    print("Option 2 –", fluree)

    # --- Option 3: JSON-LD config with env var ---
    os.environ.setdefault("FLUREE_ENCRYPTION_KEY", b64_key)   # set for demo

    config = {
        "@context": {"@vocab": "https://ns.flur.ee/system#"},
        _K_GRAPH: [{
            _K_TYPE: "Connection",
            "indexStorage": {
                _K_TYPE: "Storage",
                "filePath": _DEFAULT_PATH,
                "AES256Key": {"envVar": "FLUREE_ENCRYPTION_KEY"},
            },
        }],
    }
    fluree = FlureeBuilder.from_json_ld(config).build_encrypted_from_config()
    print("Option 3 –", fluree)


if __name__ == "__main__":
    main()
