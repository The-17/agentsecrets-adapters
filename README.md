# agentsecrets-adapters

Community rotation provider adapters for AgentSecrets Cloud. Versioned,
content-addressed communication recipes (endpoints, auth, mint/test/retire)
executed by the isolated resolver with each tenant's **own** credentials and
quota. No credentials live in this repo — ever.

- **Spec:** `schema/adapter-v1.json` (JSON Schema, structural source of truth).
  Normative prose lives in the docs repo (`adapter-registry/01`).
- **Adapters:** `adapters/<id>/<version>.yaml` + `fixtures/` per operation.
- **Index:** `registry.json` (CI-generated, do not hand-edit).

**Availability ≠ activation:** merging a version publishes it globally as a
pinnable option. No existing rotation arm ever migrates automatically —
tenants re-arm explicitly with a visible diff. See CONTRIBUTING.

## Tooling

Everything the pipeline needs, runnable locally (Python 3.12):

```bash
pip install -r tools/requirements.txt

# Gate one descriptor, or the whole tree (static half of the vetting gate):
python tools/gate/gate.py check adapters/postgres/1.0.0.yaml
python tools/gate/gate.py check --all

# Drift classification for a proposed version bump (new-adapter|major|minor|patch):
python tools/gate/gate.py drift adapters/postgres/1.0.0.yaml

# Fail-closed secret-shaped string scan (CANARY_* sentinels are the only allowed):
python tools/gate/gate.py scan-secrets

# Regenerate registry.json (the ONLY writer; never hand-edit):
python tools/publish/regen.py --check          # verify committed file is in sync

# Sign listed versions (Ed25519, key from REGISTRY_SIGNING_KEY):
python tools/publish/sign.py
python tools/publish/sign.py --verify-only     # fail closed on bad/missing signature

# Tests for all of the above:
python -m pytest tools/ -q
```

Gate behaviour is fail-closed by construction: anything the gate cannot decide
is a rejection and goes to human review, never an open door.

## Lifecycle

```
draft  --[regenerate: hash filled]-->  in_review  --[verdict:list]-->  listed
   \                                                                      /
    `---------------------------- revoked <-------------------------------`
```

- `draft` → `in_review` happens automatically once the gate is green and the
  push lands on `main`; **nothing lists itself**.
- `in_review` → `listed` requires a human verdict carried on the merged PR as
  the label `verdict:list` (or a `Registry-Verdict: list` commit trailer for
  direct pushes).
- `revoked` is a registry-state operation. Removing a descriptor file without
  the revocation flow fails the publish job on purpose.

## Signing

Listed versions carry an Ed25519 signature over the raw 32 bytes of the
descriptor's content hash. The key lives in CI as the repo secret
`REGISTRY_SIGNING_KEY` (64 hex chars = 32-byte seed). Until it is configured,
publish fills hashes and moves statuses but leaves versions
**signature-pending** with a loud warning — never falsely marked signed.
Verification trusts only the operator-configured key; a public key recorded in
`registry.json` is a claim, not trust.
