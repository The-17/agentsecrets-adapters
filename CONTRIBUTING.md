# Contributing adapters

## Before you write anything

1. Read the descriptor spec (normative prose in the docs repo,
   `adapter-registry/01-adapter-spec.md`; structural schema here:
   `schema/adapter-v1.json`).
2. Pick the closest template: `adapters/postgres/1.0.0.yaml` (database /
   `sql` ops) or `adapters/cloudflare-api-token/1.2.0.yaml` (REST / `http`
   ops). Copy the shape, not the values.

## Submission checklist (PR must include all of these)

- [ ] `adapters/<id>/<version>.yaml` — valid against `schema/adapter-v1.json`,
      semver version, new version (no overwriting published versions).
- [ ] `adapters/<id>/fixtures/{mint,test,retire}.json` (`precheck.json` if
      declared) — recorded request/response pairs using `CANARY_*` sentinels
      for all secret-shaped values. **No real credentials anywhere** — CI
      scans for secret-shaped strings and fails closed.
- [ ] Least-privilege permissions documented in the PR description (what scopes
      the minted credential needs and why — advisory, but reviewers read it).

## Run the gate yourself first

Identical checks run in CI, so there is no reason to guess:

```bash
pip install -r tools/requirements.txt
python tools/gate/gate.py check adapters/<your-id>/<your-version>.yaml
python tools/gate/gate.py scan-secrets
python -m pytest tools/ -q
```

The gate rejects on: schema violations, wildcard/IP/loopback/own-infrastructure
hosts, unknown auth primitives, header injection attempts, admin credentials in
URLs, `minted_credential` outside test steps, more than one extracted field,
non-mint `extract`, tests without assertions, non-idempotent retire, missing or
malformed fixtures, an extraction path that does not resolve against your mint
fixture, and any secret-shaped string outside `CANARY_*`.

## What happens after you open the PR

1. **Automated gate** (CI, minutes): gate unit tests → JSON Schema → static
   host/auth/extraction checks → fixture contract → canary scan. Failure =
   job summary + exit code, fix and push. CI also labels the PR with its drift
   class (`drift:major`, `drift:minor`, `drift:patch`, `drift:new-adapter`).
2. **Human review.** Merging on `main` re-gates the merged bytes, fills the
   content hash, and moves your version to `in_review`. That is availability
   staging — not listing.
3. **Verdict.** A maintainer applies the `verdict:list` label to the merged PR
   (or writes `Registry-Verdict: list` as a commit trailer). Only then does the
   version become `listed`, globally pinnable, and signed.
4. **Availability ≠ activation.** Nobody's existing rotations change — tenants
   opt in per arm with a diff. That rule is load-bearing; it is not negotiable.

Without a `verdict:list` signal your version stays `in_review` indefinitely.
Silence is not approval.

## Ground rules

- One extracted credential field per adapter. If your provider needs more,
  open an issue — don't smuggle extra fields through `track`.
- Retire must be idempotent (tolerate already-gone).
- Test must prove the *minted* credential authenticates, not just that the
  API is reachable.
- Never list our infrastructure, localhost, IPs, or non-HTTPS endpoints.
- Versions are immutable. A fix = a new version.
