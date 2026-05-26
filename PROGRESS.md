# T&S Engineering Project — Progress Log

## Goal
Entry level T&S Engineering role at Vercel

## Connection
Have a contact at Vercel — reach out after Week 4 
with completed project

## Current Status
Week 3 Monday complete — modular architecture built

## What's Been Built

### Week 1 — URL Risk Classifier ✅
Location: week-1-url-risk-classifier/
Final file: friday-risk-scorer.js
What it does: Keyword based URL scanner with weighted 
scoring, deployment objects, batch processing, 
error handling

### Week 2 — Deployment Scanner ✅
Location: week-2-deployment-scanner/
Final file: friday-deployment-scanner.js
What it does: Multi-signal scanner combining URLScan.io
and Google Safe Browsing APIs with keyword scoring.
Detected real phishing sites during development.

### Week 3 — Threat Signal Aggregator (in progress)
Location: week-3-threat-signal-aggregator/
Current file: src/index.js
Architecture: Fully modular ES6 imports
Monday done: All 7 modules built and running

## Week 3 Remaining Days

### Tuesday
- Add velocity detection signal
- New file: src/signals/velocity.js
- Checks how many times a domain has been 
  scanned recently — high velocity = suspicious

### Wednesday  
- Add domain age signal via WhoisXML API
- New file: src/signals/domainAge.js
- New domains (under 30 days) score higher risk
- Sign up free at whoisxmlapi.com

### Thursday
- Integrate velocity and domain age into fusion.js
- Update signal weights in config.js
- Retest against known threats

### Friday
- Complete Week 3 build
- Full system test with all 5 signals
- Update README

## Week 4 Plan (not started)
- Express API wrapper around the scanner
- React frontend dashboard
- User can type any URL and get live verdict
- Deploy backend to Railway.app
- Frontend already on Vercel
- THIS IS THE DEMO FOR YOUR CONNECTION

## Tech Stack
- JavaScript / Node.js
- ES6 modules (import/export)
- dotenv for environment variables
- URLScan.io API
- Google Safe Browsing API
- WhoisXML API (coming Tuesday)

## APIs In Use
- URLScan.io — scan ID search + verdict fetch
- Google Safe Browsing v4 — threatMatches endpoint
- Both keys stored in .env files per project

## Key Concepts Learned
- Variables, data types, functions
- Arrays and array methods (map, filter, sort)
- Objects, methods, factory functions
- Error handling, custom errors, try/catch
- Async/await and Promises
- Fetch API and real HTTP requests
- ES6 modules and import/export
- Multi-signal fusion and weighted scoring
- Professional modular architecture

## GitHub
https://github.com/DylanMackley/ts-engineering-projects

## Project Structure
ts-engineering-projects/
├── week-1-url-risk-classifier/
├── week-2-deployment-scanner/
└── week-3-threat-signal-aggregator/
    └── src/
        ├── config.js
        ├── validators.js
        ├── fusion.js
        ├── reporter.js
        ├── index.js
        └── signals/
            ├── keywords.js
            ├── urlscan.js
            └── google.js