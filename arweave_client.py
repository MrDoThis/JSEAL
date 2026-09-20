"""
Optional Arweave archival for JSeal certificates (architecture doc Phase 2).

Disabled by default — the rest of the system (signing, live verification)
works completely without this. Set ARWEAVE_ENABLED=true and
ARWEAVE_WALLET_PATH to a funded Arweave wallet's JWK file to turn it on.

IMPORTANT — sandbox testing note: everything in this file up to the actual
network broadcast (wallet loading, transaction construction, local RSA
signing) was tested directly and works. The live `.send()` call to
arweave.net could not be tested from the sandbox this was built in, since
that environment's network egress only allows a fixed list of package
registries. Test this file's upload_bundle() against a real, funded wallet
before relying on it for a live event.

A failed or unreachable Arweave upload NEVER blocks certificate issuance —
this function only logs and returns None on any failure. A live event
running on flaky wifi should never have signing itself fail because an
archival step timed out.
"""
import os
import json
import logging

logger = logging.getLogger("jseal.arweave")

_wallet = None
_wallet_load_attempted = False


def _get_wallet():
    global _wallet, _wallet_load_attempted
    if _wallet_load_attempted:
        return _wallet
    _wallet_load_attempted = True

    wallet_path = os.getenv("ARWEAVE_WALLET_PATH")
    if not wallet_path or not os.path.exists(wallet_path):
        logger.info("ARWEAVE_WALLET_PATH not set or file missing — Arweave archival disabled.")
        return None

    try:
        import arweave
        _wallet = arweave.Wallet(wallet_path)
        logger.info(f"Arweave wallet loaded: {_wallet.address}")
    except Exception as e:
        logger.warning(f"Could not load Arweave wallet: {e}")
        _wallet = None

    return _wallet


def is_enabled() -> bool:
    return os.getenv("ARWEAVE_ENABLED", "false").lower() == "true" and _get_wallet() is not None


def upload_bundle(cert_id: str, bundle: dict) -> str | None:
    """Uploads a signed certificate bundle to Arweave, tagged for later
    lookup. Returns the transaction ID, or None if archival is disabled,
    unavailable, or the upload failed for any reason.

    The bundle shape here MUST match what verify-standalone.html's
    tryArweave() expects: {certificate_id, payload, signature.signature_hex, ...}
    — see buildSignedBundle() in jseal-studio.html for the canonical shape.
    """
    if not is_enabled():
        return None

    try:
        import arweave
        wallet = _get_wallet()
        tx = arweave.Transaction(wallet, data=json.dumps(bundle))
        tx.add_tag("App-Name", "JSeal")
        tx.add_tag("Content-Type", "application/json")
        tx.add_tag("Cert-Id", cert_id)
        tx.sign()
        tx.send()
        logger.info(f"Archived {cert_id} to Arweave: {tx.id}")
        return tx.id
    except Exception as e:
        # Never let an Arweave hiccup block certificate issuance.
        logger.warning(f"Arweave upload failed for {cert_id}: {e}")
        return None
