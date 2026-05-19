# Week 1 — URL Risk Classifier

A keyword-based URL scanner that detects suspicious patterns 
commonly found in phishing deployments.

## What It Does
Takes a URL string, checks it against a list of high-risk keywords 
commonly used in phishing attacks, and returns a structured verdict 
with matched signals and a risk decision.

## T&S Use Case
First signal layer in a phishing detection system. Targets the naming 
patterns attackers use when deploying credential harvesting pages on 
hosting platforms like Vercel.

## How To Run
```bash
node monday-keyword-detector.js
```

## Signals Detected
- login, verify, secure, account, update
- confirm, password, signin, banking, authentication

## What I'd Add Next
- Weighted scoring so high risk keywords score higher than others
- Regex patterns to catch variations like "l0gin" or "verif-y"
- Integration with URLScan.io API to go beyond keyword matching


### tuesday-url-filter.js
Batch scans a list of URLs using array methods, separates 
results into risk groups, and produces a triage report 
sorted by threat severity.

## T&S Use Case
First signal layer in a phishing detection system targeting 
deployment abuse patterns on hosting platforms like Vercel.

## How To Run
```bash