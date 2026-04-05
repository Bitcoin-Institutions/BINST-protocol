# BINST Metaprotocol Schema

JSON schema for Ordinals inscriptions with `metaprotocol: "binst"`.

## Envelope format

Every BINST inscription uses the Ordinals envelope:
- **Content type** (tag 1) = `application/json`
- **Metaprotocol** (tag 7) = `binst`
- **Parent** (tag 3) = parent inscription ID (provenance chain)
- **Metadata** (tag 5) = optional CBOR-encoded metadata
- **Body** = JSON matching this schema

## Entity types

| Type | Parent requirement | Purpose |
|---|---|---|
| `institution` | BINST root inscription | Institution identity and metadata |
| `process_template` | Institution inscription | Immutable process blueprint |
| `process_instance` | Process template inscription | Running execution of a template |
| `step_execution` | Process instance inscription | Record of a step execution (optional) |
| `state_digest` | Institution inscription | Periodic index linking activity to Bitcoin DA |

## Provenance hierarchy

```
BINST Root (metaprotocol: "binst", type: not set — just the root)
 └─ institution (child of root)
     ├─ process_template (child of institution)
     │   └─ process_instance (child of template)
     │       └─ step_execution (child of instance)
     └─ state_digest (child of institution)
         └─ prev_digest → previous state_digest (linked list)
```

## Schema version

`"v": 0` — pilot / testnet4. Breaking changes increment the version.

## Files

- `binst-metaprotocol.json` — JSON Schema (2020-12)
- `examples/institution.json` — example institution inscription body
- `examples/process_template.json` — example process template
- `examples/process_instance.json` — example process instance
- `examples/step_execution.json` — example step execution
- `examples/state_digest.json` — example state digest (DA index)

## Validating

```bash
# With ajv-cli (npm install -g ajv-cli)
ajv validate -s binst-metaprotocol.json -d examples/institution.json
```
