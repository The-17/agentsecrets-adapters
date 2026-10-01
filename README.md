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
