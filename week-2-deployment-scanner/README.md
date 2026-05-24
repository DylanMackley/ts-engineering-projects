# Week 2 — Deployment Scanner

A production-quality multi-signal URL scanner that combines 
three independent threat intelligence sources to detect 
malicious deployments on hosting platforms.

## What This System Does
Takes any URL or batch of URLs and runs them simultaneously 
against three signal sources, fuses the results into a 
combined confidence score, and produces a prioritized triage 
report with recommended enforcement actions.

## Signal Sources
- **Keyword Scoring** — weighted detection of phishing 
  patterns in URL structure (Week 1 logic)
- **URLScan.io** — real-time scanning and behavioral 
  analysis of deployed pages
- **Google Safe Browsing** — Google's confirmed threat 
  database updated from billions of Chrome users

## Verdict Tiers
- 🔴 HIGH (70+ pts) — Auto Takedown
- 🟡 MEDIUM (40-69 pts) — Escalate to Human Review
- 🟠 LOW (10-39 pts) — Monitor
- 🟢 CLEAN (0-9 pts) — Clear

## Real Threats Detected During Development
- htyd.vercel.app — confirmed phishing (URLScan score 100)
- instagrmm.vercel.app — Instagram impersonation (Google: SOCIAL_ENGINEERING)
- interac-online.vercel.app — bank impersonation (Google: SOCIAL_ENGINEERING)
- bank-sco.vercel.app — financial fraud (Google: SOCIAL_ENGINEERING)

## Files
- monday-env-setup.js — API key setup, first real URLScan call
- tuesday-urlscan-api.js — two-call pattern, full verdict retrieval
- wednesday-safe-browsing-api.js — Google Safe Browsing integration
- thursday-multi-signal-scanner.js — signal fusion engine
- friday-deployment-scanner.js — complete production build

## How To Run
```bash
node friday-deployment-scanner.js
```

## Key Engineering Decisions
**Why multi-signal?** URLScan and Google disagreed on every 
threat in testing. URLScan caught what Google missed. Google 
caught what URLScan missed. Neither source alone was sufficient.

**Why tiered actions?** Auto takedown requires high confidence 
to protect against false positives. Lower confidence signals 
get human review rather than automated enforcement.

**Why keyword scoring?** APIs have rate limits and don't always 
have data on brand new deployments. Keywords provide an 
immediate first-pass signal with zero API dependency.