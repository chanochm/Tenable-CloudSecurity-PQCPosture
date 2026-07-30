---
slug: tenable-cloudsecurity-pqcposture
name: PQC Posture Portal
author: chanochm
github_url: https://github.com/chanochm/Tenable-CloudSecurity-PQCPosture
description: Self-hosted web portal that scores post-quantum cryptography readiness for every internet-facing cloud resource from Tenable Cloud Security's native SSL/TLS PQC telemetry — live dashboard, resource table, and per-resource crypto drill-down. Connects straight to the Hexa AI MCP server, zero dependencies.
license: MIT
type: agent
tier: contributed
framework: Python stdlib
integrations:
  - Tenable
  - Tenable Hexa AI MCP
  - AWS
  - Azure
  - GCP
tags:
  - post-quantum
  - pqc
  - cryptography
  - ml-kem
  - kyber
  - tls
  - cloud-security
  - cspm
  - dashboard
  - key-exchange
  - harvest-now-decrypt-later
  - crypto-agility
  - tenable-cloud-security
  - hexa
---

A self-hosted web portal that answers one question about your cloud estate: **which internet-facing resources would survive a quantum adversary, and which would not?**

It reads Tenable Cloud Security's native `SSL/TLS PQC Support` telemetry — not inferred cipher heuristics — and turns it into a dashboard, a filterable resource inventory, and a per-resource cryptographic drill-down. Paste a service account token into the setup screen and it queries your tenant directly through the **Tenable Hexa AI MCP server** — no AI client at runtime, no model in the data path. Python standard library only: no pip install, no Node, no build step.

## Why post-quantum posture is a today problem

Any endpoint negotiating a classical key exchange (ECDHE, DHE, RSA) is breakable by Shor's algorithm on a sufficiently capable quantum computer. An adversary can record that traffic **now** and decrypt it **later** — the harvest-now, decrypt-later problem. NIST has standardised ML-KEM, and regulators have started asking for migration plans, which makes "what fraction of our estate is quantum-ready?" a question security teams are now expected to answer with evidence.

## What it does

- **Scores each resource** on the native PQC field — `Enforced`, `Ready`, or `None` — across all of its endpoints, rather than guessing from cipher suite names
- **Recomputes every verdict server-side on each request** from the raw endpoint fields, so a stale or hand-edited snapshot can never produce a misleading dashboard
- **Distinguishes post-quantum key exchange from classical** across the full group vocabulary: `Mlkem512/768/1024`, `X25519Mlkem768`, `Secp256R1Mlkem512/768`, `Secp384R1Mlkem1024`, `Mlkem512X25519`, `CurveSm2Mlkem768`, and the draft Kyber hybrids — versus elliptic-curve, Brainpool, GOST and FFDHE groups
- **Works on locked-down corporate networks out of the box** — Python normally ignores
  the OS certificate store, so a TLS-inspecting proxy or private CA that Chrome accepts
  will break it. The portal reads the macOS keychains and Windows certificate stores
  natively (no pip install), and if trust still fails it shows you the issuer and
  fingerprint with one-click remediation, including certificate pinning for private CAs
- **Stores your credential encrypted at rest** with a per-install key file, binds localhost only, rejects non-local `Host` headers to block DNS rebinding, and never writes the token to a log or an API response
- **Sends nothing anywhere except Tenable** — no telemetry, no font CDN, no analytics. Skip the connection step entirely and the bundled demo runs with networking disabled

## Four verdicts

| Verdict | Meaning |
| --- | --- |
| **Quantum-safe** | PQC enforced, or ready on every endpoint, on a modern protocol |
| **Review** | Partial PQC coverage, or a legacy protocol (TLS 1.1 or below) still enabled |
| **Not quantum-safe** | Classical key exchange only — exposed to harvest-now, decrypt-later |
| **No crypto data** | Exposed but unscanned; posture unknown rather than falsely clean |

That last verdict matters: if your tenant's Cloud Security build doesn't expose the PQC fields yet, resources report **No crypto data** instead of a zero that looks like a clean bill of health.

## Dashboard

The portal opens on a dashboard modelled on Tenable Vulnerability Management's
**Post-Quantum Cipher Analysis** dashboard, rebuilt entirely on Cloud Security data —
so a team that already knows the Tenable VM view gets the same shape for their cloud
estate. Seven widgets: services using PQC, services *not* using PQC, which post-quantum
ciphers were discovered (broken out by port and protocol), cipher inventory by service,
TLS weaknesses, certificate expiry bucketed by urgency, and a live countdown to the
**Executive Order 14412** deadlines — 31 December 2030 for key establishment,
31 December 2031 for digital signatures, 2035 for full quantum resistance.

Where Cloud Security has no equivalent signal, the widget states that rather than
fabricating one: SSH algorithm weaknesses and Nessus plugin severities are host-scan
concepts, and Asset Criticality Rating has no Cloud Security counterpart. A dashboard
that quietly fills gaps with zeros is worse than one that admits them.

The hero is a **lattice** — one diamond per scanned endpoint, coloured by PQC status, so the ratio of quantum-ready to classical infrastructure is legible at a glance. The motif is not decorative: ML-KEM is lattice-based cryptography.

Three analytical panels sit beneath it:

- **Resources by verdict** — click any verdict to filter the inventory to it
- **Key exchange profiles** — the distinct sets of KEX groups actually offered across the estate, with post-quantum groups highlighted and an endpoint count per profile. This is the panel that shows *how* the fleet is configured, not just whether it passes
- **Negotiated cipher suites** — with the reminder that quantum resistance is decided at the key-exchange layer, not by the symmetric cipher, which is the single most common misconception about PQC readiness

## Resource drill-down

Clicking any row opens a slide-over panel with the verdict and a plain-language explanation of *why* it scored that way, every endpoint's host / port / protocol / TLS version / negotiated cipher and PQC status, the **complete set of offered key-exchange groups** with post-quantum ones marked, and a deep link into the AWS, Azure, GCP or OCI console for that resource.

For a resource scoring **Not quantum-safe**, the panel shows the classical groups it does offer — typically the full ECC and FFDHE ladder — making it immediately clear that the gap is a missing hybrid group, not a weak cipher.

## Getting the data

Click **Connection**, paste a service account token from **Settings → Access
Management**, and hit **Save & test**. The portal speaks MCP JSON-RPC to
`https://app.tenable.com/api/mcp` itself and pages through the results. Access
key / secret key pairs and non-production MCP URLs are both supported.

Every query is a plain UDM document under `queries/` — nothing is hard-coded — so you
can edit a filter, add a field, or author an entirely new view without touching the
Python. Live sync and the offline snapshot produce the **same document**, which means
the render path is deterministic and reproducible.

## Built for schema drift

The native PQC fields depend on your Cloud Security build. On connect the portal probes
`udm_get_object_type_metadata`; if `TlsPqcStatus` is missing it switches to a legacy
query, marks the dashboard **inferred**, and hides the widgets that would otherwise show
zeros. A dashboard must never turn an absent field into a clean bill of health.

## Requirements

Python 3.8+. Nothing else.
