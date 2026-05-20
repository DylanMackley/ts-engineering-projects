# Week 1 — URL Risk Classifier

A keyword-based URL scanner that detects suspicious patterns 
commonly found in phishing deployments on hosting platforms.

## T&S Use Case
First signal layer in a phishing detection system targeting 
deployment abuse patterns at infrastructure companies like Vercel.
Models the core detection logic used in real T&S systems —
signal collection, risk scoring, structured case creation,
and graceful error handling.

---

## Files

### monday-keyword-detector.js
Detects suspicious keywords in a single URL and returns a 
structured verdict with matched signals and a risk decision.
Concepts: variables, data types, comparisons, conditionals, functions

### tuesday-url-filter.js
Batch scans a list of URLs using array methods, separates 
results into risk groups, and produces a triage report 
sorted by threat severity.
Concepts: arrays, map, filter, find, some, sort

### wednesday-deployment-object.js
Models flagged deployments as structured objects with their 
own properties and methods. Factory function creates consistent 
deployment objects automatically from scan results.
Concepts: objects, methods, this, factory functions

### thursday-error-handling.js
Adds professional error handling to every function in the 
pipeline. Custom named errors for every failure type. System 
stays running and returns structured results even on bad input.
Concepts: try/catch, throw, custom errors, finally

### friday-risk-scorer.js (coming tomorrow)
Combines all four days into one complete working system.

---

## How To Run

```bash
node monday-keyword-detector.js
node tuesday-url-filter.js
node wednesday-deployment-object.js
node thursday-error-handling.js
```

---

## Signals Detected
login, verify, secure, account, update, confirm,
password, signin, banking, authentication

---

## Risk Levels
- 🔴 HIGH — 3 or more signals matched
- 🟡 MEDIUM — 1 to 2 signals matched  
- 🟢 LOW — 0 signals matched
- ⚪ UNKNOWN — scan failed due to invalid input

---

## What I'd Add Next
- Weighted scoring so high risk keywords score higher than others
- Regex patterns to catch variations like "l0gin" or "verif-y"
- Real API integration replacing hardcoded test URLs
- Persistent storage to track URLs scanned over time
- Rate limiting to prevent abuse of the scanner itself