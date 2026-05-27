cat > week-3-threat-signal-aggregator/README.md << 'EOF'
# Week 3 — Threat Signal Aggregator

A 6-signal threat detection system built on a modular ES6 architecture. Each signal runs concurrently and contributes independently to a weighted combined score. Produces terminal triage reports and structured JSON exports after every scan.

## Signals

| Signal | Source | What It Detects |
|---|---|---|
| `keywords` | Static analysis | Suspicious patterns in URL structure |
| `urlscan` | URLScan.io API | Live scan verdict and malicious score |
| `google` | Google Safe Browsing API | Confirmed blocklist hits |
| `velocity` | URLScan.io search | High scan frequency = active campaign |
| `domainAge` | RDAP (no API key) | Newly registered domains = fresh attack infrastructure |
| `sslAge` | Node `tls` handshake | Fresh SSL cert = new subdomain deployment |

## Architecture
index.js              ← orchestrator
├── validators.js     ← URL validation
├── config.js         ← weights, thresholds, endpoints
├── signals/
│   ├── keywords.js   ← static scoring
│   ├── urlscan.js    ← URLScan.io API
│   ├── google.js     ← Google Safe Browsing API
│   ├── velocity.js   ← scan frequency analysis
│   ├── domainAge.js  ← RDAP registration lookup
│   └── sslAge.js     ← TLS cert inspection
├── fusion.js         ← signal fusion + verdict
└── reporter.js       ← terminal output + JSON export

## Fusion Logic

All 6 signals run concurrently via `Promise.all`. Each contributes a weighted score to a combined total. Verdicts are assigned by threshold:
70+  → HIGH   (AUTO TAKEDOWN)
40+  → MEDIUM (ESCALATE TO HUMAN REVIEW)
10+  → LOW    (MONITOR)
0    → CLEAN

Override rules can escalate verdicts independent of score. A confirmed Google Safe Browsing hit always floors at HIGH. If a signal errors, its weight is redistributed and the system continues in degraded mode.

## Key Engineering Decisions

**SSL age is gated on corroboration** — only contributes when at least one other signal has already fired. Vercel rotates certs frequently so a fresh cert alone is not sufficient signal and would generate false positives on legitimate deployments.

**Domain age uses apex domain** — RDAP only accepts registered domains, not subdomains. This is a known limitation: subdomain abuse on aged infrastructure like `vercel.app` defeats domain age signals. SSL cert age was built specifically to address this gap.

**Signals never throw** — every signal returns a structured error object on failure. The system always produces a verdict even with partial signal data.

## Setup

```bash
npm install
cp .env.example .env
# Add your API keys to .env
node src/index.js
```

## API Keys Required

- **URLScan.io** — free at https://urlscan.io/user/signup
- **Google Safe Browsing** — free at https://developers.google.com/safe-browsing

## Output

Every scan produces a timestamped JSON report in `reports/`:

```json
{
  "meta": { "tool": "Threat Signal Aggregator", "version": "3.0" },
  "summary": { "high": 1, "medium": 3, "low": 2, "clean": 2 },
  "cases": [...]
}
```
EOF
