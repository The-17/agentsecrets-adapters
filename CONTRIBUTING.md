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

## What happens after you open the PR

1. **Automated gate** (CI, minutes): schema validation → static host/auth/
   extraction checks → conformance run against your fixtures → canary
   leak-fuzz. Failure = inline annotations, fix and push.
2. **Human review** (if triggered): new provider domains, auth changes, or
   `major` drift always get a reviewer; routine bumps from established
   authors usually don't. SLA: 5 business days, queue position visible.
3. **Merge = publish availability.** The version becomes globally pinnable
   with our signature. Nobody's existing rotations change — tenants opt in
   per arm with a diff. That rule is load-bearing; it is not negotiable.

## Ground rules

- One extracted credential field per adapter. If your provider needs more,
  open an issue — don't smuggle extra fields through `track`.
- Retire must be idempotent (tolerate already-gone).
- Test must prove the *minted* credential authenticates, not just that the
  API is reachable.
- Never list our infrastructure, localhost, IPs, or non-HTTPS endpoints.
- Versions are immutable. A fix = a new version.
