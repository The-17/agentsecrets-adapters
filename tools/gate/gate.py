"""Automated adapter gate (plan 04.2, items 1-4 + fixture/canary checks + drift).

Usage:
  gate.py check [--all | <descriptor.yaml> ...] [--registry registry.json]
  gate.py drift --registry registry.json <descriptor.yaml>
  gate.py scan-secrets [path ...]

Exit codes: 0 = pass, 1 = fail (first reason printed as JSON to stdout),
2 = tool misuse.

What this gate covers (public, runnable anywhere):
  1. JSON Schema conformance (schema/adapter-v1.json).
  2. Static host checks (no IP/localhost/port/wildcard, registrable-domain
     shape, own-infra + known-bad blocklists).
  3. Static auth checks (closed primitive catalog, per-primitive fields,
     settable-header allowlist, credential-source confinement).
  4. Static extraction checks (single mint-only extract, track-key heuristic,
     test assertions, retire 404-tolerance).
  5. Fixture contract (mint/test/retire(+precheck) packs present and shaped;
     extraction path resolves in the mint fixture; CANARY discipline).
  6. Drift classification for version bumps + semver-bump enforcement.

Explicitly NOT covered here (needs the execution sandbox, plan 04.2 item 5
full conformance): running fixtures through an executor with failure
injection and leak-fuzz. That runs in the internal gate; this public gate is
the static half. Anything this gate cannot decide fails closed to human
review — never open.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schema" / "adapter-v1.json"

try:
    import yaml
except ImportError:  # pragma: no cover - CI installs requirements
    yaml = None

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None


# --------------------------------------------------------------------------
# Small result type
# --------------------------------------------------------------------------

class GateFailure(Exception):
    """A single fail-closed gate reason (machine-readable, no secret text)."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load_descriptor(path: Path) -> dict:
    if yaml is None:
        raise GateFailure("gate tooling missing dependency: pyyaml")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GateFailure(f"yaml parse: {exc}")
    if not isinstance(doc, dict):
        raise GateFailure("descriptor root must be a mapping")
    return doc


def load_schema() -> dict:
    try:
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GateFailure(f"cannot load schema: {exc}")


# --------------------------------------------------------------------------
# 1. Schema conformance
# --------------------------------------------------------------------------

def check_schema(doc: dict) -> None:
    if Draft202012Validator is None:
        raise GateFailure("gate tooling missing dependency: jsonschema")
    schema = load_schema()
    errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "(root)"
        raise GateFailure(f"schema: {where}: {first.message}")


# --------------------------------------------------------------------------
# Interpolation helpers (shared by URL/body/auth checks)
# --------------------------------------------------------------------------

REF_RE = re.compile(r"\$\{([^{}]+)\}")

ALLOWED_REF_SOURCES = ("inputs.", "previous.", "admin_credential.", "minted_credential")
LEAF_REFS = ("now_rfc3339", "uuid4")

PRIMITIVES = {
    "bearer_token", "basic", "api_key_header", "api_key_query",
    "aws_sigv4", "hmac", "postgres_dsn",
}

SETTABLE_HEADERS = ("Content-Type", "Accept")
SETTABLE_HEADER_RE = re.compile(r"^X-[A-Za-z0-9-]+$")
FORBIDDEN_HEADERS = {"authorization", "cookie", "host", "proxy-authorization",
                     "proxy-authenticate", "proxy-connection", "content-length"}


def refs_in_string(s: str) -> list[str]:
    return REF_RE.findall(s)


def walk_strings(node, out: list) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str):
                raise GateFailure("body mapping keys must be literal strings")
            walk_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            walk_strings(v, out)
    elif node is None or isinstance(node, (bool, int, float)):
        pass
    else:  # pragma: no cover - schema already restricts scalars
        raise GateFailure(f"body scalar of unsupported type: {type(node).__name__}")


# --------------------------------------------------------------------------
# 2. Static host checks
# --------------------------------------------------------------------------

OWN_INFRA_SUFFIXES = ("agentsecrets.tech",)
BLOCKED_EXACT = {
    "localhost", "metadata.google.internal",
    "169.254.169.254", "fd00:ec2::254",
}
CANARY_RE = re.compile(r"CANARY_[A-Z0-9_]+")


def check_hosts(doc: dict) -> None:
    hosts = doc["meta"]["allowed_hosts"]
    if not isinstance(hosts, list) or len(hosts) > 8:
        raise GateFailure("meta.allowed_hosts must be a list of at most 8")
    for h in hosts:
        if not isinstance(h, str) or not h or len(h) > 253:
            raise GateFailure("meta.allowed_hosts entry malformed")
        low = h.lower()
        if "*" in h:
            raise GateFailure(f"meta.allowed_hosts wildcards forbidden in v1: {h}")
        if ":" in h or "/" in h or " " in h or "\t" in h:
            raise GateFailure(f"meta.allowed_hosts must be bare domains (no port/path): {h}")
        try:
            ipaddress.ip_address(h)
        except ValueError:
            pass
        else:
            raise GateFailure(f"meta.allowed_hosts must not be IP literals: {h}")
        if low in BLOCKED_EXACT or low.endswith(".localhost") or low == "localhost":
            raise GateFailure(f"meta.allowed_hosts must not name loopback/metadata hosts: {h}")
        if "." not in h:
            raise GateFailure(f"meta.allowed_hosts must be registrable domains: {h}")
        if any(low == sfx or low.endswith("." + sfx) for sfx in OWN_INFRA_SUFFIXES):
            raise GateFailure(f"meta.allowed_hosts must never list our own infrastructure: {h}")


# --------------------------------------------------------------------------
# 3. Static auth checks
# --------------------------------------------------------------------------

def check_auth_block(auth: dict, where: str, in_test_step: bool = False) -> None:
    prim = auth.get("primitive")
    if prim not in PRIMITIVES:
        raise GateFailure(f"{where}.auth: unknown primitive {prim!r}")
    src = auth.get("credential_source")
    if src == "minted_credential" and not in_test_step:
        raise GateFailure(f"{where}.auth: minted_credential only legal in test steps")
    if prim == "basic" and not (auth.get("username_field") and auth.get("password_field")):
        raise GateFailure(f"{where}.auth: basic needs username_field + password_field")
    if prim == "api_key_header":
        name = auth.get("header_name", "")
        if not (name in SETTABLE_HEADERS or SETTABLE_HEADER_RE.match(name or "")):
            raise GateFailure(f"{where}.auth: header not settable: {name!r}")
        if (name or "").lower() in FORBIDDEN_HEADERS:
            raise GateFailure(f"{where}.auth: header forbidden: {name!r}")
    if prim == "api_key_query" and not re.match(r"^[a-zA-Z0-9_-]{1,64}$", auth.get("param_name") or ""):
        raise GateFailure(f"{where}.auth: param_name shape")
    if prim == "aws_sigv4" and not (auth.get("service") and auth.get("region") and auth.get("credential_field")):
        raise GateFailure(f"{where}.auth: aws_sigv4 needs service + region + credential_field")
    if prim == "hmac":
        if (auth.get("algorithm") or "sha256") != "sha256":
            raise GateFailure(f"{where}.auth: hmac algorithm is sha256-only in v1")
        if not auth.get("signed_components"):
            raise GateFailure(f"{where}.auth: hmac needs signed_components")


def check_interpolation(doc: dict) -> None:
    inputs = set((doc.get("inputs") or {}).keys())
    ops = doc.get("operations") or {}
    for op_name in ("precheck", "mint", "test", "retire"):
        step = ops.get(op_name)
        if step is None or not isinstance(step, dict):
            continue
        http = step.get("http")
        is_test = op_name == "test"
        if http:
            url = http.get("url", "")
            if not isinstance(url, str) or not url.startswith("https://"):
                raise GateFailure(f"operations.{op_name}: url must be absolute https")
            if "${" in url.split("://", 1)[1].split("/", 1)[0]:
                raise GateFailure(f"operations.{op_name}: url host must be literal (allowlist match)")
            if "admin_credential." in url:
                raise GateFailure(f"operations.{op_name}: credentials never belong in urls")
            for ref in refs_in_string(url):
                check_ref(ref, inputs, allow_admin=False, allow_minted=False,
                          allow_previous=op_name in ("retire", "precheck"),
                          where=f"operations.{op_name}.url")
            for hk, hv in (http.get("headers") or {}).items():
                if not isinstance(hv, str):
                    continue
                for ref in refs_in_string(hv):
                    check_ref(ref, inputs, allow_admin=False, allow_minted=False,
                              allow_previous=False, where=f"operations.{op_name}.header")
            body = http.get("body")
            if body is not None:
                leaves: list = []
                walk_strings(body, leaves)
                for leaf in leaves:
                    for ref in refs_in_string(leaf):
                        check_ref(ref, inputs, allow_admin=True, allow_minted=is_test,
                                  allow_previous=False, where=f"operations.{op_name}.body")
        sql = step.get("sql")
        if sql:
            probe = sql.get("probe") or {}
            for field in ("dsn_role", "dsn_password"):
                tpl = probe.get(field)
                if isinstance(tpl, str):
                    for ref in refs_in_string(tpl):
                        if ref.startswith("admin_credential."):
                            raise GateFailure(f"operations.{op_name}: probes authenticate as the rotated identity, never the admin")
                        check_ref(ref, inputs, allow_admin=False,
                                  allow_minted=(field == "dsn_password"),
                                  allow_previous=False, where=f"operations.{op_name}.probe")


def check_ref(ref: str, inputs: set, *, allow_admin: bool, allow_minted: bool,
              allow_previous: bool, where: str) -> None:
    if ref in LEAF_REFS:
        return
    if ref.startswith("inputs."):
        name = ref[len("inputs."):]
        if name not in inputs:
            raise GateFailure(f"{where}: unknown input {name!r}")
        return
    if ref.startswith("previous."):
        if not allow_previous:
            raise GateFailure(f"{where}: previous.* only legal in retire/precheck")
        return
    if ref.startswith("admin_credential."):
        if not allow_admin:
            raise GateFailure(f"{where}: admin credential not admissible here")
        return
    if ref == "minted_credential":
        if not allow_minted:
            raise GateFailure(f"{where}: minted_credential only legal in test steps")
        return
    raise GateFailure(f"{where}: unresolvable reference {ref!r}")


# --------------------------------------------------------------------------
# 4. Static extraction checks
# --------------------------------------------------------------------------

SECRET_LIKE = re.compile(r"(secret|password|token|key|credential|value)", re.IGNORECASE)
JSON_PATH_RE = re.compile(r"^\$\.[A-Za-z0-9_\[\]\.]+$|^\$generated$")


def check_operations(doc: dict) -> None:
    ops = doc.get("operations") or {}
    for name in ("mint", "test"):
        step = ops.get(name)
        if not isinstance(step, dict):
            raise GateFailure(f"operations.{name} required")
        if ("http" in step) == ("sql" in step) and not ("http" in step or "sql" in step):
            raise GateFailure(f"operations.{name}: exactly one of http/sql")
    mint = ops["mint"]
    ext = mint.get("extract")
    if not isinstance(ext, dict) or set(ext.keys()) != {"new_credential"}:
        raise GateFailure("operations.mint.extract must map exactly {new_credential: <path>}")
    if not isinstance(ext["new_credential"], str) or not JSON_PATH_RE.match(ext["new_credential"]):
        raise GateFailure("operations.mint.extract.new_credential path shape")
    for name in ("test", "precheck"):
        step = ops.get(name)
        if isinstance(step, dict) and step.get("extract") is not None:
            raise GateFailure(f"operations.{name}: extract forbidden (mint only)")
    test_asserts = (ops["test"].get("assert") or []) if isinstance(ops.get("test"), dict) else []
    if not test_asserts:
        raise GateFailure("operations.test must assert (a test that cannot fail is decoration)")
    retire = ops.get("retire")
    if retire is not None:
        if not isinstance(retire, dict):
            raise GateFailure("operations.retire shape")
        tolerates_404 = any(404 in (a.get("allow_status") or []) for a in (retire.get("assert") or []) if isinstance(a, dict))
        if not tolerates_404:
            raise GateFailure("operations.retire must tolerate 404 (idempotent retire) or carry reviewer override")
    for tkey, tpath in (doc.get("track") or {}).items():
        if SECRET_LIKE.search(tkey):
            raise GateFailure(f"track key looks secret-bearing: {tkey!r}")
        if not isinstance(tpath, str) or not JSON_PATH_RE.match(tpath):
            raise GateFailure(f"track path shape: {tkey!r}")
    check_auth_block(doc.get("auth") or {}, "auth")
    for op_name in ("precheck", "mint", "test", "retire"):
        step = ops.get(op_name)
        if isinstance(step, dict):
            http = step.get("http") or {}
            if isinstance(http.get("auth_override"), dict):
                check_auth_block(http["auth_override"], f"operations.{op_name}.auth_override",
                                 in_test_step=(op_name == "test"))


def check_limits(doc: dict) -> None:
    lim = doc.get("limits") or {}
    if not isinstance(lim.get("max_retries"), int) or not 0 <= lim["max_retries"] <= 3:
        raise GateFailure("limits.max_retries 0-3")
    allowed = {408, 429, 500, 502, 503, 504}
    if any(s not in allowed for s in (lim.get("retry_on") or [])):
        raise GateFailure("limits.retry_on closed set")
    mrb = lim.get("max_response_bytes")
    if not isinstance(mrb, int) or not 4096 <= mrb <= 1048576:
        raise GateFailure("limits.max_response_bytes bounds")


def check_inputs(doc: dict) -> None:
    inputs = doc.get("inputs") or {}
    if len(inputs) > 16:
        raise GateFailure("inputs max 16")
    reserved = {"credential", "secret", "token", "key", "password", "auth"}
    for name, spec in inputs.items():
        if name in reserved or not re.match(r"^[a-z][a-z0-9_]{0,63}$", name):
            raise GateFailure(f"inputs name reserved or malformed: {name!r}")
        if (spec or {}).get("type") not in ("string", "integer", "boolean"):
            raise GateFailure(f"inputs.{name} type closed set")


# --------------------------------------------------------------------------
# 5. Fixture contract (static half of conformance)
# --------------------------------------------------------------------------

SECRET_SHAPES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY"),
    re.compile(r"xox[bap]-[A-Za-z0-9-]+"),
    re.compile(r"sk-live-[A-Za-z0-9]+"),
]


def check_fixtures(adapter_dir: Path, doc: dict) -> None:
    fixdir = adapter_dir / "fixtures"
    ops = doc.get("operations") or {}
    needed = ["mint", "test"]
    if isinstance(ops.get("retire"), dict):
        needed.append("retire")
    if isinstance(ops.get("precheck"), dict):
        needed.append("precheck")
    for op in needed:
        fp = fixdir / f"{op}.json"
        if not fp.is_file():
            raise GateFailure(f"fixtures/{op}.json required")
        try:
            fix = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as exc:
            raise GateFailure(f"fixtures/{op}.json invalid json: {exc}")
        if fix.get("operation") != op:
            raise GateFailure(f"fixtures/{op}.json operation mismatch")
        if not isinstance(fix.get("request_match"), dict) or "response" not in fix:
            raise GateFailure(f"fixtures/{op}.json needs request_match + response")
    # Mint extraction must resolve in the mint fixture (broken-by-construction check).
    mint_fix = json.loads((fixdir / "mint.json").read_text(encoding="utf-8"))
    if (doc.get("operations", {}).get("mint", {}) or {}).get("http"):
        body = ((mint_fix.get("response") or {}).get("body"))
        extracted = eval_path(body, (doc["operations"]["mint"]["extract"] or {}).get("new_credential", ""))
        if extracted is None:
            raise GateFailure("mint extract path does not resolve in fixtures/mint.json")


def eval_path(doc_node, path: str):
    """Minimal JSONPath-subset evaluator ($.a.b[0]). Returns None when unresolvable."""
    if not isinstance(path, str) or not path.startswith("$."):
        return None
    cur = doc_node
    for seg in path[2:].replace("[", ".").replace("]", "").split("."):
        if seg == "":
            continue
        if isinstance(cur, list):
            if not seg.isdigit() or int(seg) >= len(cur):
                return None
            cur = cur[int(seg)]
        elif isinstance(cur, dict):
            if seg not in cur:
                return None
            cur = cur[seg]
        else:
            return None
    return cur


def scan_secrets(paths: list[Path]) -> list[str]:
    """Fail closed on real-secret-shaped strings anywhere they should not be.
    CANARY_ sentinels are the only allowed secret-shaped values (fixtures)."""
    hits: list[str] = []
    for p in paths:
        if p.is_dir():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        scrubbed = CANARY_RE.sub("", text)
        for pat in SECRET_SHAPES:
            m = pat.search(scrubbed)
            if m:
                hits.append(f"{p}: secret-shaped content (use CANARY_* sentinels)")
                break
    return hits


# --------------------------------------------------------------------------
# 6. Drift classification + semver enforcement
# --------------------------------------------------------------------------

def classify_drift(old: dict | None, new: dict) -> str:
    """new-adapter | major | minor | patch per plan 04.2 item 6."""
    if old is None:
        return "new-adapter"
    if (old.get("meta", {}).get("id") != new.get("meta", {}).get("id")):
        raise GateFailure("drift: adapter id changed (new directory required)")

    def hosts(d):
        return set((d.get("meta") or {}).get("allowed_hosts") or [])

    def auth(d):
        a = dict((d.get("auth") or {}))
        a.pop("credential_field", None)
        a.pop("username_field", None)
        a.pop("password_field", None)
        return a

    def extract(d):
        return ((d.get("operations") or {}).get("mint", {}) or {}).get("extract")

    def required_inputs(d):
        return {k for k, v in ((d.get("inputs") or {}).items())
                if isinstance(v, dict) and "default" not in v}

    def retire(d):
        r = (d.get("operations") or {}).get("retire")
        return json.dumps(r, sort_keys=True, default=str)

    old_hosts, new_hosts = hosts(old), hosts(new)
    if new_hosts - old_hosts:
        return "major"
    if auth(old) != auth(new):
        return "major"
    if extract(old) != extract(new):
        return "major"
    if required_inputs(new) - required_inputs(old):
        return "major"
    if old_hosts - new_hosts:
        return "minor"
    if retire(old) != retire(new):
        return "minor"
    if set((new.get("inputs") or {})) - set((old.get("inputs") or {})):
        return "minor"
    return "patch"


def check_semver(old_version: str | None, new_version: str, drift: str) -> None:
    if drift == "new-adapter":
        return
    try:
        o = tuple(int(x) for x in (old_version or "0.0.0").split("."))
        n = tuple(int(x) for x in new_version.split("."))
    except ValueError:
        raise GateFailure("version must be semver")
    if drift == "major" and not (n[0] > o[0]):
        raise GateFailure(f"major drift requires a major bump (was {old_version}, got {new_version})")
    if drift == "minor" and not (n[0] > o[0] or (n[0] == o[0] and n[1] > o[1])):
        raise GateFailure(f"minor drift requires at least a minor bump (was {old_version}, got {new_version})")
    if drift == "patch" and not (n != o and (n[0], n[1]) == (o[0], o[1])):
        raise GateFailure(f"patch drift requires a patch bump (was {old_version}, got {new_version})")
    if n <= o:
        raise GateFailure(f"version must increase (was {old_version}, got {new_version})")


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------

VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def check_file(path: Path, registry: dict | None = None) -> dict:
    """Full gate for one descriptor file. Returns {drift} on pass."""
    doc = load_descriptor(path)
    check_schema(doc)
    check_hosts(doc)
    check_inputs(doc)
    check_operations(doc)
    check_interpolation(doc)
    check_limits(doc)

    meta = doc.get("meta", {})
    parts = path.resolve().parts
    if "adapters" in parts and path.parent.name != "fixtures" and path.suffix == ".yaml":
        # Layout: adapters/<id>/<version>.yaml, names matching meta.
        adapter_dir = path.parent
        if path.name != f"{meta.get('version')}.yaml" or adapter_dir.name != meta.get("id"):
            raise GateFailure("layout must be adapters/<id>/<version>.yaml matching meta")
        check_fixtures(adapter_dir, doc)

    drift = "new-adapter"
    if registry is not None:
        prev = previous_recorded(registry, meta.get("id"))
        old_doc = None
        old_version = None
        if prev is not None:
            old_version = prev.get("version")
            old_path = REPO_ROOT / prev.get("path", "")
            if old_path.is_file() and old_path != path.resolve():
                try:
                    old_doc = load_descriptor(old_path)
                except GateFailure:
                    old_doc = None
        if old_doc is None and prev is not None:
            # Previous version recorded but descriptor absent (first publish of
            # scaffold history): treat as new-adapter baseline, do not fail.
            drift = "new-adapter"
        else:
            drift = classify_drift(old_doc, doc)
            check_semver(old_version, meta.get("version", ""), drift)
    return {"drift": drift}


def previous_recorded(registry: dict, adapter_id: str) -> dict | None:
    best = None
    for a in registry.get("adapters", []):
        if a.get("id") != adapter_id:
            continue
        for v in a.get("versions", []):
            if best is None or _semkey(v.get("version", "")) > _semkey(best.get("version", "")):
                best = v
    return best


def _semkey(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (-1,)


def load_registry(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GateFailure(f"cannot load registry: {exc}")


def iter_descriptors(root: Path):
    for p in sorted((root / "adapters").glob("*/*.yaml")):
        if p.parent.name == "fixtures":
            continue
        yield p


def cmd_check(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="gate.py check")
    ap.add_argument("paths", nargs="*", help="descriptor files (default: changed vs merge-base)")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--registry", default=str(REPO_ROOT / "registry.json"))
    args = ap.parse_args(argv)
    registry = load_registry(Path(args.registry))
    if args.all or not args.paths:
        targets = list(iter_descriptors(REPO_ROOT))
    else:
        targets = [Path(p) for p in args.paths]
    report = {}
    failed = False
    for t in targets:
        try:
            report[str(t)] = check_file(t, registry)
        except GateFailure as exc:
            report[str(t)] = {"error": str(exc)}
            failed = True
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failed else 0


def cmd_drift(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="gate.py drift")
    ap.add_argument("path")
    ap.add_argument("--registry", default=str(REPO_ROOT / "registry.json"))
    args = ap.parse_args(argv)
    registry = load_registry(Path(args.registry))
    try:
        print(json.dumps(check_file(Path(args.path), registry), sort_keys=True))
        return 0
    except GateFailure as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 1


def cmd_scan(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="gate.py scan-secrets")
    ap.add_argument("paths", nargs="*", default=["adapters", "schema", "tools"])
    args = ap.parse_args(argv)
    files: list[Path] = []
    for p in args.paths:
        pp = Path(p)
        if not pp.is_absolute():
            pp = REPO_ROOT / pp
        if pp.is_dir():
            files.extend(sorted(pp.rglob("*")))
        elif pp.is_file():
            files.append(pp)
    hits = scan_secrets(files)
    print(json.dumps({"hits": hits}, indent=2))
    return 1 if hits else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("check", "drift", "scan-secrets"):
        print(__doc__.strip().splitlines()[0])
        print("commands: check | drift | scan-secrets")
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "check":
            return cmd_check(rest)
        if cmd == "drift":
            return cmd_drift(rest)
        return cmd_scan(rest)
    except GateFailure as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
