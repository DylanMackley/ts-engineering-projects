# Trust & Safety Engineering Portfolio

Self-taught T&S tooling built while learning security engineering fundamentals from the ground up.

**Goal:** Entry-level T&S Engineering role at an infrastructure company like Vercel  
**Focus:** Infrastructure abuse detection, phishing detection, deployment risk scoring  
**Stack:** JavaScript, Node.js, React

---

## Why This Exists

Vercel and similar infrastructure platforms face constant abuse from bad actors who deploy phishing pages, malware, and credential harvesting sites on top of legitimate infrastructure. The `vercel.app` domain is trusted — attackers exploit that trust.

T&S engineers build the systems that detect and stop this. These projects simulate that exact work, starting from zero and building toward a production-grade multi-signal detection platform connected to real threat intelligence APIs.

Every tool in this repo has detected real active threats during development.

---

## Projects

### ✅ Week 1 — URL Risk Classifier

A complete phishing detection pipeline built from scratch. Scans URLs for suspicious signals, assigns weighted risk scores, builds structured case files, and produces prioritized triage reports.

**Built with:** JavaScript, Node.js  
**Concepts:** Keyword detection, weighted scoring, batch processing, object modeling, error handling

---

### ✅ Week 2 — Deployment Scanner

Connects the Week 1 engine to real threat intelligence APIs. Scans deployed URLs against live databases and fuses multiple signals into a single verdict.

**Built with:** JavaScript, Node.js, URLScan.io API, Google Safe Browsing API  
**Concepts:** Async/await, Promise.all, API integration, multi-signal fusion, environment variables

**Real threats detected during development:**
- `htyd.vercel.app` — confirmed malicious by URLScan (score 100)
- `instagrmm.vercel.app` — SOCIAL_ENGINEERING (Google Safe Browsing)
- `interac-online.vercel.app` — SOCIAL_ENGINEERING (Google Safe Browsing)
- `bank-sco.vercel.app` — SOCIAL_ENGINEERING (Google Safe Browsing)

---

### ✅ Week 3 — Threat Signal Aggregator

A 6-signal threat detection system with modular ES6 architecture. Each signal runs concurrently and contributes independently to a weighted combined score. Produces both terminal triage reports and structured JSON exports.

**Built with:** JavaScript, Node.js, URLScan.io API, Google Safe Browsing API, RDAP, Node `tls`  
**Concepts:** Modular architecture, signal fusion, concurrent API calls, behavioral analysis, TLS inspection

#### Signal Architecture

| Signal | Source | What It Detects |
|---|---|---|
| `keywords` | Static analysis | Suspicious patterns in URL structure |
| `urlscan` | URLScan.io API | Live scan verdict and malicious score |
| `google` | Google Safe Browsing API | Confirmed blocklist hits |
| `velocity` | URLScan.io search | Abnormal scan frequency = active campaign |
| `domainAge` | RDAP (free, no key) | Newly registered domains = fresh attack infra |
| `sslAge` | Node `tls` handshake | Fresh SSL certs on subdomains = new deployment |

#### System Architecture
index.js          ← orchestrator, runs the pipeline
├── validators.js ← URL validation before hitting APIs
├── config.js     ← all weights, thresholds, endpoints
├── signals/
│   ├── keywords.js   ← static scoring, no API
│   ├── urlscan.js    ← URLScan.io live scan
│   ├── google.js     ← Google Safe Browsing lookup
│   ├── velocity.js   ← URLScan search frequency analysis
│   ├── domainAge.js  ← RDAP registration date lookup
│   └── sslAge.js     ← TLS handshake cert inspection
├── fusion.js     ← weighted score aggregation + override rules
└── reporter.js   ← terminal output + JSON file export

#### How Fusion Works

All 6 signals run concurrently via `Promise.all`. Each contributes a weighted score to a combined total. Override rules can escalate verdicts independent of score — a confirmed Google Safe Browsing hit always floors at HIGH regardless of other signals. If a signal errors, its weight is redistributed and the system continues in degraded mode.
Combined Score → Verdict
70+  → HIGH   (AUTO TAKEDOWN)
40+  → MEDIUM (ESCALATE TO HUMAN REVIEW)
10+  → LOW    (MONITOR)
0    → CLEAN  (CLEAR)

#### Key Engineering Decisions

**SSL age gates on corroboration** — the SSL cert age signal only contributes when at least one other signal has already fired. This prevents fresh Vercel certs on legitimate deployments from generating false positives. Vercel rotates certs frequently — SSL age alone is not sufficient signal.

**Domain age uses apex domain** — RDAP only accepts registered domains, not subdomains. `htyd.vercel.app` queries `vercel.app`, which was registered in 2020. This is a known limitation: subdomain abuse on aged infrastructure defeats domain age signals entirely. SSL cert age was built specifically to address this gap.

**Signals never throw** — every signal returns a structured error object on failure rather than throwing. Fusion checks `signal.error` and excludes that signal from the weighted average. The system always produces a verdict even with partial signal data.

#### Sample Output
🔴 #1 [HIGH] https://htyd.vercel.app/
Score:    84
Action:   AUTO TAKEDOWN
Signals:  urlscan_malicious(+45), urlscan_score(+30), velocity(+9)
Velocity: 10 scans/7d (medium)
🟡 #2 [MEDIUM] https://interac-online.vercel.app/
Score:    69
Action:   ESCALATE TO HUMAN REVIEW
Signals:  velocity(+19), google_threat(+50)
Velocity: 100 scans/7d (critical)
📄 JSON report saved → reports/report-2026-05-27T20-01-01.json

---

### ✅ Week 4 — Phishing Detector

Content-based phishing detection that goes beyond URL analysis. Fetches live page HTML and runs 4 independent analyzers to detect credential harvesting, brand impersonation, and malicious form behavior — catching phishing pages that are too new to appear in any blocklist.

**Built with:** JavaScript, Node.js, node-html-parser, React  
**Concepts:** HTTP content fetching, DOM analysis, brand similarity detection, credential pattern matching, React dashboard

#### Analyzer Architecture

| Analyzer | What It Detects |
|---|---|
| `forms` | Forms submitting to external domains, hidden field exfiltration |
| `brands` | Brand names appearing on wrong domains (PayPal on non-paypal.com) |
| `credentials` | Password fields, SIN, CVV, card numbers on same page |
| `title` | Page titles impersonating known brands |

#### Real Detections
🟡 https://paypal-secure-login.vercel.app/  — Score 68
Form submits to evil-collector.com
Brand "paypal" on wrong domain
Password field + credential keywords detected
Title impersonates PayPal
🟡 https://interac-verify-account.vercel.app/  — Score 55
CRITICAL: Password and credit card fields on same page
SIN, CVV, card number fields detected
Brand "interac" on wrong domain
Title impersonates Interac

#### Dashboard

A React triage dashboard visualizes scan results with per-case signal breakdowns and a side-by-side signal matrix. Built directly from the JSON reports the CLI produces.
week-4-phishing-detector/
├── src/
│   ├── analyzers/    ← forms, brands, credentials, title
│   ├── fetcher.js    ← HTML fetcher with timeout + size limit
│   ├── fusion.js     ← weighted analyzer score aggregation
│   ├── reporter.js   ← terminal output + JSON export
│   └── index.js      ← orchestrator
└── dashboard/
└── TSDashboard.jsx  ← React triage dashboard

---

## Signal Design Philosophy

Each signal is designed to be:

- **Independent** — signals don't share state or call each other
- **Non-blocking** — one signal failure never stops the pipeline
- **Additive** — signals corroborate, they don't override each other except via explicit fusion rules
- **Explainable** — every fired signal produces a human-readable evidence string

This mirrors how production T&S systems work: no single signal is trusted absolutely. Verdicts emerge from the weight of independent evidence.

---

## Running the System

```bash
git clone https://github.com/DylanMackley/ts-engineering-projects.git

# Week 3 — Threat Signal Aggregator (6 signals, requires API keys)
cd week-3-threat-signal-aggregator
npm install
cp .env.example .env   # add URLScan.io + Google Safe Browsing keys
node src/index.js

# Week 4 — Phishing Detector (content analysis, no API keys needed)
cd week-4-phishing-detector
npm install
node src/index.js
```

API keys required for Week 3:
- URLScan.io — free at https://urlscan.io/user/signup
- Google Safe Browsing — free at https://developers.google.com/safe-browsing

---

## What I'm Learning

Building these tools while studying how real T&S teams operate at infrastructure companies. The core insight from this work: effective abuse detection is less about any single signal and more about the architecture that lets signals operate independently and combine reliably.

The hardest problems aren't detecting known threats — blocklists handle that. The hard problems are detecting new attacks with no prior signal, minimizing false positives on legitimate deployments, and building systems that degrade gracefully when external APIs fail.

Those are the problems this portfolio is designed to demonstrate I can think about.
