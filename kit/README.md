# Your AVA access kit — read me first

You have been granted **query access** to a data owner's AVA gate. You will
never receive the data itself — you receive **answers** (counts, existence,
sums, means) computed inside the owner's sealed environment, through a key
the owner can revoke at any time. Every question you ask is recorded in a
tamper-evident audit log.

## What the owner should have given you

| Item | Looks like | Keep it |
|---|---|---|
| Gate URL | `https://gate.example.org` | anywhere |
| Your bearer key | `ava_…` | **secret** — it is your identity |
| Audit public key | `audit_signing.pub` (PEM file) | with this kit |
| Expected image digest | `sha256:…` *(enclave rollouts only)* | with this kit |

Received the key over the same channel as the URL? Ask the owner to confirm
the audit key's fingerprint over a **second** channel (call, in person).

## Step 1 — verify before you trust (2 minutes)

```bash
python3 ava_verify.py --gate <GATE_URL> --key ava_yourkey \
    --audit-pub audit_signing.pub
```

Needs only Python 3.9+ — no packages. It checks that the gate is up, that
it holds the audit key the owner published (fingerprint match), and that
your key returns an answer — and *only* an answer. Anything other than
`RESULT: VERIFIED`: stop and contact the owner.

## Step 2 — ask questions

```bash
curl -s <GATE_URL>/query \
  -H "Authorization: Bearer ava_yourkey" -H "Content-Type: application/json" \
  -d '{"type":"count","category":"alpha","ts_from":"2026-01-01"}'
```

Query types: `count`, `exists`, `sum`, `mean`. Filters: `category`, `zone`,
`ts_from`/`ts_to`; add `"target":"media"` (+ optional `"media_type"`) to ask
about the owner's media holdings, and `"type":"attest"` for a cryptographic
commitment to the matched set — **attest requires trusted status**, granted
per consumer by the owner (a `403` means ask them). That list is closed —
there is no endpoint that returns records, files, or identifiers, by design.

**Save every response.** `query_id` + `audit_entry_hash` + `computed_at`
are your receipt: they pin your query into the owner's hash-chained,
signed audit log, and the owner can later prove exactly what was answered.

## Previews, revocation, and 4xx errors

- **Previews** (degraded, watermarked samples) exist only under a
  time-boxed grant the owner issues; if you have a `grant_id`, POST it to
  `/preview`. Grants expire on their own.
- **401** — key unknown (typo, or never issued). **403** — key revoked:
  access is the owner's decision, and it takes effect within one request.
  Either way, the conversation to have is with the owner, not the gate.
