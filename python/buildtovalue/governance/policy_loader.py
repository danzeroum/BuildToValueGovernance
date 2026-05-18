"""
PolicyLoader — Ed25519 signature verification for policy YAMLs (ADR-064).

Separation of Powers: the Ethics Committee signs with its private key; the
Executive verifies with the public key — it never possesses the private key.

Fail-secure: ``verify_policy_yaml`` returns ``False`` (never raises) on any
verification failure, so an invalid or missing key always rejects the policy.
"""
import base64
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger(__name__)


def _get_pubkey_path() -> str:
    """Resolve public-key path lazily so tests can monkeypatch the env var."""
    path = os.environ.get(
        "BTV_POLICY_PUBKEY_PATH", "data/keys/ethics_committee_pubkey.pem"
    )
    if "BTV_POLICY_PUBKEY_PATH" not in os.environ:
        logger.warning(
            "BTV_POLICY_PUBKEY_PATH not set; using default '%s' (ADR-064).", path
        )
    return path


def load_ethics_committee_pubkey() -> Ed25519PublicKey:
    """Load the Ethics Committee Ed25519 public key from the configured PEM file."""
    pem = Path(_get_pubkey_path()).read_bytes()
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(
            f"BTV_POLICY_PUBKEY_PATH must point to an Ed25519 public key, "
            f"got {type(key).__name__}"
        )
    return key


def verify_policy_yaml(yaml_bytes: bytes, signature_b64: str) -> bool:
    """Verify the Ed25519 signature of a policy YAML produced by the Ethics Committee.

    Fail-secure: returns ``False`` (never raises) on any error so an invalid
    or missing signature always results in the policy being rejected.

    Args:
        yaml_bytes: Raw bytes of the YAML policy file.
        signature_b64: Base64-encoded Ed25519 signature produced by the Ethics Committee.

    Returns:
        ``True`` if the signature is valid; ``False`` otherwise.
    """
    try:
        pubkey = load_ethics_committee_pubkey()
        sig = base64.b64decode(signature_b64)
        pubkey.verify(sig, yaml_bytes)
        return True
    except InvalidSignature:
        logger.error("Policy YAML Ed25519 signature is INVALID (ADR-064).")
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("Policy YAML signature verification FAILED: %s", exc)
        return False
