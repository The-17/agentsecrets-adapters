"""Tests for registry publish tooling (plan 09.3).

Covers: hash fill, new-version drafts, immutability, missing-file
revocation rule, verdict transitions (never auto-list, never downgrade),
check mode, and signing round-trip. Run: pytest tools/publish/test_publish.py
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "gate"))
from gate import GateFailure  # noqa: E402
from regen import (  # noqa: E402
    apply_verdict,
    content_hash,
    regenerate,
)


def min_doc(adapter_id="ex", version="1.0.0"):
    return {
        "meta": {"id": adapter_id, "version": version,
                 "display_name": "Ex", "allowed_hosts": ["api.example.com"]},
        "auth": {"primitive": "bearer_token", "credential_source": "admin_credential",
                 "credential_field": "api_token"},
        "inputs": {"name": {"type": "string"}},
        "operations": {
            "mint": {
                "http": {"method": "POST", "url": "https://api.example.com/t",
                         "body": {"name": "${inputs.name}"}},
                "timeout_seconds": 10,
                "extract": {"new_credential": "$.value"},
                "assert": [{"path": "$.ok", "equals": True}],
            },
            "test": {
                "http": {"method": "GET", "url": "https://api.example.com/v"},
                "timeout_seconds": 10,
                "assert": [{"path": "$.ok", "equals": True}],
            },
            "retire": None,
        },
        "track": {},
        "limits": {"max_retries": 0, "retry_on": [],
                   "max_response_bytes": 4096, "step_timeout_seconds": 10},
    }


def write_tree(root: Path, docs: dict) -> None:
    """docs: {(adapter_id, version): descriptor_dict}"""
    for (aid, ver), doc in docs.items():
        d = root / "adapters" / aid
        (d / "fixtures").mkdir(parents=True, exist_ok=True)
        (d / f"{ver}.yaml").write_text(yaml.safe_dump(doc))
        for op in ("mint", "test"):
            (d / "fixtures" / f"{op}.json").write_text(json.dumps({
                "operation": op, "request_match": {},
                "response": {"status": 200, "body": {"ok": True, "value": "CANARY_X"}}}))


def empty_registry():
    return {"generated_by": "test", "spec_version": 1, "adapters": []}


def test_canonical_hash_stable():
    a = min_doc()
    b = dict(reversed(list(a.items())))
    assert content_hash(a) == content_hash(b)
    assert content_hash(a).startswith("sha256:")
    c = dict(a)
    c["meta"] = dict(a["meta"], version="9.9.9")
    assert content_hash(c) != content_hash(a)


def _regen_with_tree(monkeypatch, tmp_path, docs, registry, files=None):
    """Run regenerate() with REPO_ROOT pointed at a fake tree."""
    import regen as regen_mod
    write_tree(tmp_path, docs)
    if files:
        for rel, text in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    monkeypatch.setattr(regen_mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr("gate.REPO_ROOT", tmp_path)
    return regenerate(registry)


def test_new_entries_arrive_as_draft(monkeypatch, tmp_path):
    import regen as regen_mod  # noqa: F401
    new, notices = _regen_with_tree(monkeypatch, tmp_path,
                                    {("ex", "1.0.0"): min_doc()}, empty_registry())
    v = new["adapters"][0]["versions"][0]
    assert v["status"] == "draft"
    assert v["content_hash"].startswith("sha256:")
    assert v["spec_version"] == 1
    assert any("draft" in n for n in notices)


def test_hash_fill_keeps_status(monkeypatch, tmp_path):
    reg = empty_registry()
    reg["adapters"] = [{"id": "ex", "namespace": "public", "author": "@t",
                        "display_name": "Ex", "description": "",
                        "versions": [{"version": "1.0.0", "path": "adapters/ex/1.0.0.yaml",
                                      "content_hash": "sha256:PENDING", "status": "draft"}]}]
    new, _ = _regen_with_tree(monkeypatch, tmp_path, {("ex", "1.0.0"): min_doc()}, reg)
    v = new["adapters"][0]["versions"][0]
    assert v["content_hash"].startswith("sha256:")
    assert v["content_hash"] != "sha256:PENDING"
    assert v["status"] == "draft"


def test_immutability_violation(monkeypatch, tmp_path):
    reg = empty_registry()
    reg["adapters"] = [{"id": "ex", "namespace": "public", "author": "@t",
                        "display_name": "Ex", "description": "",
                        "versions": [{"version": "1.0.0", "path": "adapters/ex/1.0.0.yaml",
                                      "content_hash": "sha256:" + "00" * 32, "status": "listed"}]}]
    with pytest.raises(GateFailure, match="immutability"):
        _regen_with_tree(monkeypatch, tmp_path, {("ex", "1.0.0"): min_doc()}, reg)


def test_missing_file_demands_revocation_flow(monkeypatch, tmp_path):
    reg = empty_registry()
    reg["adapters"] = [{"id": "ex", "namespace": "public", "author": "@t",
                        "display_name": "Ex", "description": "",
                        "versions": [{"version": "1.0.0", "path": "adapters/ex/1.0.0.yaml",
                                      "content_hash": "sha256:" + "00" * 32, "status": "listed"}]}]
    (tmp_path / "adapters").mkdir()
    monkeypatch.setattr(sys.modules["regen"], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules["gate"], "REPO_ROOT", tmp_path)
    with pytest.raises(GateFailure, match="revocation"):
        regenerate(reg)


def test_verdict_never_auto_lists():
    reg = {"adapters": [{"id": "ex", "versions": [{"version": "1.0.0", "status": "draft"}]}]}
    apply_verdict(reg, "none")
    assert reg["adapters"][0]["versions"][0]["status"] == "in_review"
    # Second run without verdict stays put (no silent promotion).
    apply_verdict(reg, "none")
    assert reg["adapters"][0]["versions"][0]["status"] == "in_review"


def test_verdict_list_promotes_once():
    reg = {"adapters": [{"id": "ex", "versions": [{"version": "1.0.0", "status": "in_review"}]}]}
    apply_verdict(reg, "list")
    assert reg["adapters"][0]["versions"][0]["status"] == "listed"


def test_verdict_never_downgrades():
    for st in ("listed", "revoked"):
        reg = {"adapters": [{"id": "ex", "versions": [{"version": "1.0.0", "status": st}]}]}
        apply_verdict(reg, "none")
        apply_verdict(reg, "list")
        assert reg["adapters"][0]["versions"][0]["status"] == st
    reg = {"adapters": [{"id": "ex", "versions": [{"version": "1.0.0", "status": "bogus"}]}]}
    with pytest.raises(GateFailure):
        apply_verdict(reg, "none")


def test_sign_roundtrip_and_verify(tmp_path, monkeypatch):
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import sign as sign_mod
    seed = Ed25519PrivateKey.generate()
    raw = seed.private_bytes_raw().hex()
    monkeypatch.setenv("TEST_REG_KEY", raw)
    reg = {"adapters": [{"id": "ex", "versions": [
        {"version": "1.0.0", "status": "listed",
         "content_hash": "sha256:" + "ab" * 32}]}]}
    rp = tmp_path / "registry.json"
    rp.write_text(json.dumps(reg))
    assert sign_mod.cmd(["--registry", str(rp), "--key-env", "TEST_REG_KEY"]) == 0
    out = json.loads(rp.read_text())
    sig = out["adapters"][0]["versions"][0]["signature"]
    assert set(sig) == {"key_id", "public_key", "signature"}
    assert sign_mod.cmd(["--registry", str(rp), "--key-env", "TEST_REG_KEY",
                         "--verify-only"]) == 0
    # Tamper: flip the hash, signature must fail.
    out["adapters"][0]["versions"][0]["content_hash"] = "sha256:" + "cd" * 32
    rp.write_text(json.dumps(out))
    assert sign_mod.cmd(["--registry", str(rp), "--key-env", "TEST_REG_KEY",
                         "--verify-only"]) == 1
    # Unknown key: wipe env, verify must fail closed (never trust recorded keys).
    monkeypatch.delenv("TEST_REG_KEY")
    assert sign_mod.cmd(["--registry", str(rp), "--key-env", "TEST_REG_KEY",
                         "--verify-only"]) == 1
