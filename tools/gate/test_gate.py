"""Tests for the automated adapter gate (plan 04.2 static half).

Every case asserts fail-closed behavior: the exact rejection reason, never a
pass on malformed input. Run: pytest tools/gate/test_gate.py
"""

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from gate import (  # noqa: E402
    GateFailure,
    check_auth_block,
    check_file,
    check_hosts,
    check_inputs,
    check_interpolation,
    check_limits,
    check_operations,
    classify_drift,
    check_semver,
    eval_path,
    scan_secrets,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTORS = REPO_ROOT / "schema" / "vectors"


def minimal_doc() -> dict:
    return {
        "meta": {
            "id": "example-min",
            "version": "0.1.0",
            "display_name": "Example Min",
            "allowed_hosts": ["api.example.com"],
        },
        "auth": {
            "primitive": "bearer_token",
            "credential_source": "admin_credential",
            "credential_field": "api_token",
        },
        "inputs": {
            "target_name": {"type": "string", "min_length": 1, "max_length": 64},
        },
        "operations": {
            "mint": {
                "http": {
                    "method": "POST",
                    "url": "https://api.example.com/tokens",
                    "body": {"name": "${inputs.target_name}"},
                },
                "timeout_seconds": 15,
                "extract": {"new_credential": "$.value"},
                "assert": [{"path": "$.ok", "equals": True}],
            },
            "test": {
                "http": {"method": "GET", "url": "https://api.example.com/verify"},
                "timeout_seconds": 15,
                "assert": [{"path": "$.ok", "equals": True}],
            },
            "retire": None,
        },
        "limits": {
            "max_retries": 1,
            "retry_on": [429, 503],
            "max_response_bytes": 65536,
            "step_timeout_seconds": 15,
        },
    }


def full_pass(doc: dict) -> None:
    from gate import check_schema
    check_schema(doc)
    check_hosts(doc)
    check_inputs(doc)
    check_operations(doc)
    check_interpolation(doc)
    check_limits(doc)


def mutate(doc: dict, path: str, value) -> dict:
    """Set dotted path (e.g. 'meta.id') on a deep copy. 'DELETE' removes."""
    out = copy.deepcopy(doc)
    node = out
    *segs, leaf = path.split(".")
    for s in segs:
        node = node[s]
    if value == "DELETE":
        node.pop(leaf, None)
    else:
        node[leaf] = value
    return out


# --- schema vectors ----------------------------------------------------------

def test_vectors_behave():
    cases = {
        "valid-minimal-http.json": "pass",
        "invalid-bad-version-and-id.json": "fail",
        "invalid-reserved-input-double-extract.json": "fail",
    }
    for name, want in cases.items():
        vec = json.loads((VECTORS / name).read_text())
        with_tmp = vec["descriptor"]
        tmp = Path("/tmp") / f"vec_{name}.yaml"
        tmp.write_text(yaml.safe_dump(with_tmp))
        try:
            if want == "pass":
                full_pass(with_tmp)
            else:
                with pytest.raises(GateFailure):
                    full_pass(with_tmp)
        finally:
            tmp.unlink(missing_ok=True)


# --- hosts --------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "127.0.0.1", "::1", "localhost", "x.localhost", "api.example.com:8443",
    "evil*.example.com", "169.254.169.254", "api.agentsecrets.tech",
    "no-dot-host", "not a host",
])
def test_host_rejections(bad):
    with pytest.raises(GateFailure):
        check_hosts(mutate(minimal_doc(), "meta.allowed_hosts", [bad]))


def test_host_ok():
    check_hosts(minimal_doc())


# --- auth ---------------------------------------------------------------------

def test_auth_primitives():
    d = minimal_doc()
    check_auth_block(d["auth"], "auth")
    with pytest.raises(GateFailure):
        check_auth_block({**d["auth"], "primitive": "magic"}, "auth")
    with pytest.raises(GateFailure):
        check_auth_block({**d["auth"], "credential_source": "minted_credential"}, "op")
    # minted source only legal in test steps
    check_auth_block({**d["auth"], "credential_source": "minted_credential"},
                     "operations.test.auth_override", in_test_step=True)


def test_auth_header_allowlist():
    d = minimal_doc()
    bad = {**d["auth"], "primitive": "api_key_header",
           "header_name": "Authorization", "credential_field": "k"}
    with pytest.raises(GateFailure):
        check_auth_block(bad, "auth")
    good = {**bad, "header_name": "X-Api-Key"}
    check_auth_block(good, "auth")


# --- interpolation confinement --------------------------------------------------

def test_admin_cred_never_in_url():
    d = minimal_doc()
    d["operations"]["mint"]["http"]["url"] = "https://api.example.com/${admin_credential.api_token}"
    with pytest.raises(GateFailure, match="never belong in urls"):
        check_interpolation(d)


def test_minted_only_in_test():
    d = minimal_doc()
    body = d["operations"]["mint"]["http"]["body"]
    body["token"] = "${minted_credential}"
    with pytest.raises(GateFailure, match="only legal in test"):
        check_interpolation(d)


def test_unknown_input_ref():
    d = minimal_doc()
    d["operations"]["mint"]["http"]["body"] = {"name": "${inputs.nope}"}
    with pytest.raises(GateFailure, match="unknown input"):
        check_interpolation(d)


def test_previous_only_in_retire():
    d = minimal_doc()
    d["operations"]["mint"]["http"]["url"] = "https://api.example.com/${previous.provider_id}"
    with pytest.raises(GateFailure, match="only legal in retire"):
        check_interpolation(d)


def test_templated_host_rejected():
    d = minimal_doc()
    d["operations"]["mint"]["http"]["url"] = "https://${inputs.host}/t"
    with pytest.raises(GateFailure, match="host must be literal"):
        check_interpolation(d)


def test_http_only():
    d = minimal_doc()
    d["operations"]["mint"]["http"]["url"] = "http://api.example.com/t"
    with pytest.raises(GateFailure, match="absolute https"):
        check_interpolation(d)


# --- extraction -----------------------------------------------------------------

def test_double_extract_rejected():
    d = minimal_doc()
    d["operations"]["test"]["extract"] = {"new_credential": "$.x"}
    with pytest.raises(GateFailure, match="mint only"):
        check_operations(d)


def test_track_key_heuristic():
    d = minimal_doc()
    d["track"] = {"api_token": "$.id"}
    with pytest.raises(GateFailure, match="secret-bearing"):
        check_operations(d)
    d["track"] = {"provider_id": "$.result.id"}
    check_operations(d)


def test_test_must_assert():
    d = minimal_doc()
    d["operations"]["test"]["assert"] = []
    with pytest.raises(GateFailure):
        check_operations(d)


def test_retire_must_tolerate_404():
    d = minimal_doc()
    d["operations"]["retire"] = {
        "http": {"method": "DELETE", "url": "https://api.example.com/t/1"},
        "timeout_seconds": 5,
        "assert": [{"path": "$.success", "equals": True}],
    }
    with pytest.raises(GateFailure, match="404"):
        check_operations(d)
    d["operations"]["retire"]["assert"] = [
        {"path": "$.success", "equals": True, "allow_status": [200, 404]}]
    check_operations(d)


def test_reserved_input_names():
    with pytest.raises(GateFailure, match="reserved"):
        check_inputs(mutate(minimal_doc(), "inputs.token", {"type": "string"}))


# --- fixtures ---------------------------------------------------------------------

def test_fixture_extraction_must_resolve(tmp_path):
    from gate import check_fixtures
    d = minimal_doc()
    fixdir = tmp_path / "fixtures"
    fixdir.mkdir()
    (fixdir / "mint.json").write_text(json.dumps({
        "operation": "mint",
        "request_match": {"method": "POST"},
        "response": {"status": 200, "body": {"ok": True, "wrong": 1}},
    }))
    (fixdir / "test.json").write_text(json.dumps({
        "operation": "test",
        "request_match": {"method": "GET"},
        "response": {"status": 200, "body": {"ok": True}},
    }))
    with pytest.raises(GateFailure, match="does not resolve"):
        check_fixtures(tmp_path, d)


def test_fixture_operation_mismatch(tmp_path):
    from gate import check_fixtures
    d = minimal_doc()
    fixdir = tmp_path / "fixtures"
    fixdir.mkdir()
    (fixdir / "mint.json").write_text(json.dumps({
        "operation": "test",
        "request_match": {},
        "response": {"status": 200, "body": {}},
    }))
    (fixdir / "test.json").write_text(json.dumps({
        "operation": "test",
        "request_match": {},
        "response": {"status": 200, "body": {}},
    }))
    with pytest.raises(GateFailure, match="mismatch"):
        check_fixtures(tmp_path, d)


def test_eval_path():
    doc = {"result": {"items": [{"value": "v"}]}}
    assert eval_path(doc, "$.result.items[0].value") == "v"
    assert eval_path(doc, "$.missing") is None
    assert eval_path(doc, "relative") is None


def test_scan_secrets_allows_canary_rejects_real(tmp_path):
    good = tmp_path / "a.txt"
    good.write_text('{"value": "CANARY_MINTED_CREDENTIAL_001"}')
    assert scan_secrets([good]) == []
    bad = tmp_path / "b.txt"
    # Built dynamically so this test file itself stays scan-clean.
    bad.write_text("key = " + "AKIA" + "IOSFODNN7EXAMPLE")
    assert len(scan_secrets([bad])) == 1


# --- drift + semver ---------------------------------------------------------------

def test_drift_new_major_minor_patch():
    base = minimal_doc()
    assert classify_drift(None, base) == "new-adapter"
    assert classify_drift(base, copy.deepcopy(base)) == "patch"
    minor = copy.deepcopy(base)
    minor["inputs"]["extra"] = {"type": "string", "default": "x"}
    assert classify_drift(base, minor) == "minor"
    major = copy.deepcopy(base)
    major["meta"]["allowed_hosts"] = ["api.example.com", "api2.example.com"]
    assert classify_drift(base, major) == "major"
    auth_change = copy.deepcopy(base)
    auth_change["auth"]["primitive"] = "basic"
    auth_change["auth"]["username_field"] = "u"
    auth_change["auth"]["password_field"] = "p"
    assert classify_drift(base, auth_change) == "major"
    extract_change = copy.deepcopy(base)
    extract_change["operations"]["mint"]["extract"] = {"new_credential": "$.other"}
    assert classify_drift(base, extract_change) == "major"
    req_input = copy.deepcopy(base)
    req_input["inputs"]["must"] = {"type": "string"}
    assert classify_drift(base, req_input) == "major"


def test_semver_enforcement():
    check_semver("1.2.3", "1.2.4", "patch")
    with pytest.raises(GateFailure):
        check_semver("1.2.3", "1.2.3", "patch")
    with pytest.raises(GateFailure):
        check_semver("1.2.3", "1.3.0", "patch")
    check_semver("1.2.3", "1.3.0", "minor")
    with pytest.raises(GateFailure):
        check_semver("1.2.3", "1.2.9", "minor")
    check_semver("1.2.3", "2.0.0", "major")
    with pytest.raises(GateFailure):
        check_semver("1.2.3", "1.9.9", "major")


# --- layout -------------------------------------------------------------------------

def test_layout_mismatch(tmp_path):
    import shutil
    dest = tmp_path / "adapters" / "wrong" / "9.9.9.yaml"
    dest.parent.mkdir(parents=True)
    d = minimal_doc()
    d["meta"]["id"] = "example-min"
    d["meta"]["version"] = "0.1.0"
    dest.write_text(yaml.safe_dump(d))
    (dest.parent / "fixtures").mkdir()
    for op in ("mint", "test"):
        (dest.parent / "fixtures" / f"{op}.json").write_text(json.dumps(
            {"operation": op, "request_match": {}, "response": {"status": 200, "body": {}}}))
    with pytest.raises(GateFailure, match="[Ll]ayout"):
        check_file(dest, {"adapters": []})
    shutil.rmtree(tmp_path / "adapters", ignore_errors=True)
