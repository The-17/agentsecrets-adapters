"""Ed25519 signing for listed adapter versions (plan 03.1, 09.3).

  sign.py [--registry PATH] [--key-env REGISTRY_SIGNING_KEY] [--write]
    Sign every listed version lacking a valid signature. Key format: 64 hex
    chars (32-byte Ed25519 seed). Stored entry, all hex:
      {"key_id": <16 hex>, "public_key": <64 hex>, "signature": <128 hex>}
    Signature covers the raw 32 content-hash bytes (plan: signature over
    content_hash). Without a key: loud warning, no changes, exit 0 — versions
    stay signature-pending and publish refuses to treat them as listed-ready.
    Configure REGISTRY_SIGNING_KEY as a repo secret to activate (CONTRIBUTING).

  sign.py --verify-only [--registry PATH] [--key-env ...]
    Fail closed (exit 1) on any listed version missing a signature, an
    unknown key_id, or a bad signature. CI publish runs this; a bad signature
    is indistinguishable from tampering, so there is no warning-only mode.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "tools" / "gate"))
from gate import GateFailure, load_registry  # noqa: E402


def load_key(env_var: str):
    raw = (os.environ.get(env_var) or "").strip()
    if not raw:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise GateFailure("signing needs the 'cryptography' package")
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        raise GateFailure(f"{env_var} must be 64 hex chars (32-byte seed)")
    if len(seed) != 32:
        raise GateFailure(f"{env_var} must be 64 hex chars (32-byte seed)")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()
    key_id = hashlib.sha256(pub).hexdigest()[:16]
    return priv, pub.hex(), key_id


def content_hash_bytes(version_entry: dict) -> bytes:
    h = version_entry.get("content_hash", "")
    if not h.startswith("sha256:"):
        raise GateFailure("version lacks a computed content_hash (run regen first)")
    try:
        raw = bytes.fromhex(h[len("sha256:"):])
    except ValueError:
        raise GateFailure("content_hash malformed")
    if len(raw) != 32:
        raise GateFailure("content_hash malformed")
    return raw


def verify_signature(version_entry: dict, keys: dict[str, str]) -> None:
    """keys: key_id -> public_key hex. Raises GateFailure on any problem."""
    sig = version_entry.get("signature")
    if not isinstance(sig, dict):
        raise GateFailure("listed version has no signature")
    kid = sig.get("key_id")
    if kid not in keys:
        # Trust-on-first-use is forbidden: unknown keys fail, always.
        raise GateFailure(f"signature from unknown key_id {kid!r}")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        raise GateFailure("signing needs the 'cryptography' package")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[kid]))
        pub.verify(bytes.fromhex(sig.get("signature", "")),
                   content_hash_bytes(version_entry))
    except Exception:
        raise GateFailure("signature invalid (indistinguishable from tampering)")


def cmd(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="sign.py")
    ap.add_argument("--registry", default=str(REPO_ROOT / "registry.json"))
    ap.add_argument("--key-env", default="REGISTRY_SIGNING_KEY")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--write", action="store_true",
                    help="persist signatures to registry.json (default with a key)")
    args = ap.parse_args(argv)
    reg_path = Path(args.registry)
    registry = load_registry(reg_path)

    listed = [(a["id"], v) for a in registry.get("adapters", [])
              for v in a.get("versions", []) if v.get("status") == "listed"]
    if not listed:
        print(json.dumps({"ok": True, "note": "no listed versions"}))
        return 0

    if args.verify_only:
        # Trust comes ONLY from the operator-configured key. Signatures
        # recorded in registry.json are claims, not trust — verifying them
        # against themselves would prove nothing.
        trusted = {}
        key = load_key(args.key_env)
        if key is not None:
            _, pub_hex, key_id = key
            trusted = {key_id: pub_hex}
        if not trusted:
            print(json.dumps({"error": "cannot verify: no signing key configured (REGISTRY_SIGNING_KEY)"}))
            return 1
        try:
            for _, v in listed:
                verify_signature(v, trusted)
        except GateFailure as exc:
            print(json.dumps({"error": str(exc)}))
            return 1
        print(json.dumps({"ok": True, "verified": len(listed)}))
        return 0

    loaded = load_key(args.key_env)
    if loaded is None:
        print(json.dumps({
            "ok": True,
            "warning": f"{args.key_env} not configured: signatures skipped, listed versions stay signature-pending",
            "pending": [f"{aid}@{v.get('version')}" for aid, v in listed if not isinstance(v.get("signature"), dict)],
        }, sort_keys=True))
        return 0
    priv, pub_hex, key_id = loaded
    changed = 0
    for _, v in listed:
        try:
            verify_signature(v, {key_id: pub_hex})
            continue
        except GateFailure:
            pass
        sig = priv.sign(content_hash_bytes(v)).hex()
        v["signature"] = {"key_id": key_id, "public_key": pub_hex, "signature": sig}
        changed += 1
    if changed:
        reg_path.write_text(json.dumps(registry, indent=2, sort_keys=False) + "\n",
                            encoding="utf-8")
    print(json.dumps({"ok": True, "signed": changed, "key_id": key_id}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return cmd(argv)
    except GateFailure as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
