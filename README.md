# T&S Engineering Projects

Trust and Safety tooling built while learning T&S 
engineering fundamentals.

**Goal:** Entry level T&S Engineering role at an 
infrastructure company like Vercel.

**Focus:** Infrastructure abuse detection, phishing 
detection, deployment risk scoring.

**Stack:** JavaScript, Node.js, Express, React

---

## Projects

### ✅ Week 1 — URL Risk Classifier
A complete phishing detection pipeline that scans URLs 
for suspicious signals, assigns weighted risk scores, 
builds structured case files, and produces prioritized 
triage reports.

Built with: JavaScript, Node.js
Concepts: keyword detection, weighted scoring, batch 
processing, object modeling, error handling

### 🔄 Week 2 — Deployment Scanner (in progress)
Connects the Week 1 detection engine to real APIs —
URLScan.io and Google Safe Browsing — to scan actual
deployed URLs against live threat databases.

### ⬜ Week 3 — Threat Signal Aggregator (coming soon)

### ⬜ Week 4 — Phishing Detector (coming soon)

---

## Why I'm Building This

Vercel and similar infrastructure platforms face constant 
abuse from bad actors deploying phishing pages, malware, 
and credential harvesting sites on their infrastructure. 
T&S engineers build the systems that detect and stop this.

These projects simulate that exact work — starting with 
core detection logic and building toward a full multi-signal 
detection platform connected to real threat intelligence APIs.