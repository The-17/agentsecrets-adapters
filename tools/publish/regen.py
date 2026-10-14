"""Registry publish tooling (plan 09.3): regenerate + sign registry.json.

registry.json is GENERATED — do not hand-edit. This tool is the only writer:

  regen.py [--check] [--apply-verdict VERDICT]
    Walk adapters/<id>/<version>.yaml, canonicalize each descriptor
    (plan 03.2: UTF-8 JSON, recursively sorted keys, no whitespace), sha256
    it, and merge into registry.json:
      - recorded (id, version) with a DIFFERENT hash  -> FAIL (versions are
        immutable/append-only; a fix is a new version).
      - recorded entry whose file is gone (status != revoked) -> FAIL with
        the revocation-flow message (removal is a registry-state op, 09.3).
      - new (id, version) -> added as draft.
      - recorded PENDING hashes are filled in.
      - everything else (status, signature, notes, display fields) preserved.
    --apply-verdict list|none: with the automated gate green, draft versions
      move to in_review; with verdict "list" (merged PR carried the
      reviewer-applied verdict:list label = human approval on the PR) they
      move to listed. Without the label nothing lists itself. Downgrades
      (listed/revoked -> anything else) are refused.
    --check: regenerate in memory and diff against the committed file; exit 1
      with instructions when they differ. CI publish uses --check semantics
      plus --apply-verdict from PR labels.

  sign.py [--verify-only] [--key-env REGISTRY_SIGNING_KEY]
    Ed25519-sign listed versions lacking valid signatures. Key format: 64 hex
    chars (32-byte seed); stored entry {key_id, public_key, signature}, all
    hex, signature over the raw 32 content-hash bytes. --verify-only fails
    closed on missing/invalid signatures (CI publish). Without a key,
    signing is skipped with a loud warning and versions stay signature-pending
    — never silently marked signed. Configure REGISTRY_SIGNING_KEY as a repo
    secret to activate (see CONTRIBUTING).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "tools" / "gate"))
from gate import (  # noqa: E402
    GateFailure,
    check_file,
    iter_descriptors,
    load_descriptor,
    load_registry,
    previous_recorded,
)


def canonical_bytes(doc: dict) -> bytes:
    """Plan 03.2 canonical form. NOTE: this hashes the descriptor content,
    never the registry.json file bytes (which are pretty-printed for humans)."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def content_hash(doc: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(doc)).hexdigest()


def regenerate(registry: dict) -> tuple[dict, list[str]]:
    """Returns (new_registry, notices). Raises GateFailure on violations."""
    by_id: dict[str, dict] = {}
    for a in registry.get("adapters", []):
        by_id.setdefault(a.get("id"), {"id": a.get("id"),
                                       "namespace": a.get("namespace", "public"),
                                       "author": a.get("author", "@agentsecrets"),
                                       "display_name": a.get("display_name", a.get("id")),
                                       "description": a.get("description", ""),
                                       "versions": []})
        for v in a.get("versions", []):
            by_id[a["id"]]["versions"].append(dict(v))

    seen: set[tuple[str, str]] = set()
    notices: list[str] = []
    for path in iter_descriptors(REPO_ROOT):
        doc = load_descriptor(path)  # yaml shape; schema enforced by gate, re-checked by callers
        meta = doc.get("meta", {})
        aid, ver = meta.get("id"), meta.get("version")
        seen.add((aid, ver))
        entry = by_id.setdefault(aid, {"id": aid, "namespace": "public",
                                       "author": meta.get("author", "@agentsecrets"),
                                       "display_name": meta.get("display_name", aid),
                                       "description": meta.get("description", ""),
                                       "versions": []})
        h = content_hash(doc)
        match = next((v for v in entry["versions"] if v.get("version") == ver), None)
        if match is not None:
            recorded = match.get("content_hash")
            if recorded not in (None, "sha256:PENDING", h):
                raise GateFailure(
                    f"immutability: {aid}@{ver} hash mismatch — versions are append-only, ship a new version")
            if recorded != h:
                match["content_hash"] = h
                notices.append(f"filled hash for {aid}@{ver}")
            match["path"] = f"adapters/{aid}/{ver}.yaml"
            match.setdefault("spec_version", 1)
        else:
            entry["versions"].append({
                "version": ver,
                "path": f"adapters/{aid}/{ver}.yaml",
                "content_hash": h,
                "spec_version": 1,
                "status": "draft",
                "signature": None,
                "note": "Added by publish; awaiting gate + review.",
            })
            notices.append(f"added {aid}@{ver} as draft")

    for aid, entry in by_id.items():
        for v in entry["versions"]:
            if (aid, v.get("version")) not in seen and v.get("status") != "revoked":
                raise GateFailure(
                    f"{aid}@{v.get('version')}: descriptor file missing — removals go through "
                    f"the revocation flow (registry state leads, repo follows), never silent deletion")
        entry["versions"].sort(key=lambda v: tuple(int(x) for x in str(v.get("version", "0")).split(".")))

    out = {
        "generated_by": "CI publish workflow (do not hand-edit; regenerates on merge)",
        "spec_version": registry.get("spec_version", 1),
        "adapters": [by_id[k] for k in sorted(by_id)],
    }
    return out, notices


def apply_verdict(registry: dict, verdict: str) -> list[str]:
    """Status transitions after a green gate. Never downgrades, never auto-lists."""
    if verdict not in ("list", "none"):
        raise GateFailure(f"unknown verdict {verdict!r}")
    notices: list[str] = []
    for a in registry.get("adapters", []):
        for v in a.get("versions", []):
            st = v.get("status")
            if st == "draft":
                v["status"] = "in_review"
                v["note"] = "Automated gate passed; awaiting human review."
                notices.append(f"{a['id']}@{v['version']}: draft -> in_review")
            elif st == "in_review" and verdict == "list":
                v["status"] = "listed"
                v["note"] = "Listed on human verdict (PR label verdict:list)."
                notices.append(f"{a['id']}@{v['version']}: in_review -> listed")
            elif st == "in_review":
                # No list verdict: stays in review. Silence is not approval.
                continue
            elif st in ("listed", "revoked"):
                continue
            else:
                raise GateFailure(f"{a['id']}@{v.get('version')}: unknown status {st!r}")
    return notices


def format_registry(registry: dict) -> str:
    return json.dumps(registry, indent=2, sort_keys=False) + "\n"


def cmd_regen(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="regen.py")
    ap.add_argument("--registry", default=str(REPO_ROOT / "registry.json"))
    ap.add_argument("--check", action="store_true",
                    help="verify committed file matches regeneration; do not write")
    ap.add_argument("--apply-verdict", default="none", choices=["none", "list"])
    args = ap.parse_args(argv)
    reg_path = Path(args.registry)
    registry = load_registry(reg_path)
    try:
        new, notices = regenerate(registry)
        # Gate every on-disk descriptor before any status moves (fail closed).
        for path in iter_descriptors(REPO_ROOT):
            check_file(path, new)
        notices.extend(apply_verdict(new, args.apply_verdict))
    except GateFailure as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 1
    if args.check:
        current = reg_path.read_text(encoding="utf-8")
        if current != format_registry(new):
            print(json.dumps({
                "error": "registry.json out of sync: run tools/publish/regen.py and commit the result",
                "notices": notices,
            }, sort_keys=True))
            return 1
        print(json.dumps({"ok": True, "notices": notices}, sort_keys=True))
        return 0
    reg_path.write_text(format_registry(new), encoding="utf-8")
    print(json.dumps({"ok": True, "notices": notices}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return cmd_regen(argv)
    except GateFailure as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
