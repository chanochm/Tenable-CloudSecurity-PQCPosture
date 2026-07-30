---
name: pqc-posture
description: >-
  Post-quantum cryptography (PQC) readiness for Tenable Cloud Security. Use when
  asked about PQC posture, quantum readiness, quantum-safe or quantum-vulnerable
  endpoints, harvest-now-decrypt-later exposure, ML-KEM / Kyber adoption, TLS key
  exchange groups, or which cloud resources still use classical-only key exchange.
  Reads Cloud Security's native SSL/TLS PQC fields over the Tenable Hexa AI MCP
  server. Also use to launch or refresh the local PQC Posture Portal. Do NOT use
  for Tenable Vulnerability Management plugin-based PQC scanning.
---

# PQC Posture — Tenable Cloud Security

Companion skill to the PQC Posture Portal. Use this for conversational analysis;
use the portal (`python3 app.py`) for a browsable dashboard.

## Requirements

A Tenable Cloud Security MCP server connected in this client — usually named
`tenable-cloud-security`. It must expose the UDM tools (`udm_execute_query`,
`udm_get_object_type_metadata`, `udm_get_query_results_count`).

## Step 1 — always confirm the fields exist first

Call `udm_get_object_type_metadata` for `NetworkEndpoint` and check for:

- `NetworkEndpointHttpResponseTlsPqcStatus` — `Enforced` | `Ready` | `None`
- `NetworkEndpointHttpResponseTlsKeyExchangeGroups` — offered KEX groups
- `NetworkEndpointHttpResponseTlsCipherSuites` — full supported cipher list

If they are absent, this tenant's build predates the PQC fields. **Say so plainly
and stop, or offer the inferred fallback with an explicit caveat.** Never report a
count of zero quantum-safe resources without stating that the field is missing —
that reads as "we are exposed" when the truth is "we cannot tell".

## Step 2 — validate before fetching

Run `udm_get_query_results_count` on a query before pulling rows. A confidently
wrong security dashboard is worse than no dashboard, and the count is the cheapest
way to catch a malformed filter.

## Step 3 — query

Reuse the saved bundles in `queries/` rather than composing from scratch:

| File | Purpose |
| --- | --- |
| `queries/fleet.json` | resources joined to endpoints, with the PQC fields |
| `queries/fleet_legacy.json` | fallback for pre-PQC tenants |
| `queries/aggregates.json` | grouped counts for the summary widgets |

Paginate with `skip` in steps of 20 while `hasMore` is true.

## Verdicts

| Verdict | Condition |
| --- | --- |
| **Quantum-safe** | Every endpoint `Enforced`, or `Ready` with none `None`, and no endpoint on TLS 1.1 or below |
| **Review** | Mixed PQC coverage across endpoints, or any legacy/weak protocol present |
| **Not quantum-safe** | All endpoints `None` — classical key exchange only |
| **No crypto data** | Exposed but no PQC telemetry captured |

A key-exchange group is post-quantum if it is one of `Mlkem512`, `Mlkem768`,
`Mlkem1024`, `Secp256R1Mlkem512`, `Mlkem512X25519`, `Secp256R1Mlkem768`,
`X25519Mlkem768`, `Secp384R1Mlkem1024`, `CurveSm2Mlkem768`,
`X25519Kyber768Draft00`, or `Secp256R1Kyber768Draft00`. Everything else —
elliptic-curve, Brainpool, GOST, FFDHE — is classical.

## Reporting guidance

- Lead with the ratio (`46 of 52 endpoints are quantum-ready`), then name the
  exceptions. A ratio is actionable; a raw count is not.
- Quantum resistance is decided at the **key-exchange** layer, not by the symmetric
  cipher. `TLS_AES_128_GCM_SHA256` appears on both safe and unsafe endpoints. Say
  this whenever someone reads the cipher column as the answer.
- Distinguish `Ready` from `Enforced`. Ready means PQC is *available*; a classical
  client will still negotiate classical. Do not call a tenant migrated because it is
  Ready.
- Surface certificate expiry (`...TlsCertificateExpirationTime`) alongside PQC. It is
  usually the more urgent finding, and reporting only the strategic risk buries it.

## Launching the portal

```bash
python3 app.py          # then open http://127.0.0.1:8787
```

Credentials are entered in the browser and stored encrypted at rest. Do not paste a
service account token into chat — it belongs in the portal's setup dialog or the MCP
client config, not in a transcript.
