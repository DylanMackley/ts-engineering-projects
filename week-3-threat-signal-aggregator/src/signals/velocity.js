// src/signals/velocity.js

import { API_ENDPOINTS } from '../config.js';

const VELOCITY_THRESHOLDS = {
  CRITICAL: { scans7d: 50, score: 95, label: 'CRITICAL' },
  HIGH:     { scans7d: 20, score: 75, label: 'HIGH'     },
  MEDIUM:   { scans7d: 8,  score: 45, label: 'MEDIUM'   },
  LOW:      { scans7d: 3,  score: 20, label: 'LOW'      },
  CLEAN:    { scans7d: 0,  score: 0,  label: 'CLEAN'    },
};

function extractDomain(input) {
  try {
    const raw = input.startsWith('http') ? input : `https://${input}`;
    const hostname = new URL(raw).hostname.toLowerCase();
    return hostname.replace(/^www\./, '');
  } catch {
    return input.replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
  }
}

function parseTimestamp(ts) {
  return new Date(ts);
}

function bucketByWindow(dates, now = new Date()) {
  const counts = { '24h': 0, '7d': 0, '30d': 0, total: dates.length };
  for (const d of dates) {
    const ageDays = (now - d) / (1000 * 60 * 60 * 24);
    if (ageDays <= 1)  counts['24h']++;
    if (ageDays <= 7)  counts['7d']++;
    if (ageDays <= 30) counts['30d']++;
  }
  return counts;
}

function scoreVelocity(counts) {
  const n = counts['7d'];
  if (n >= VELOCITY_THRESHOLDS.CRITICAL.scans7d) return VELOCITY_THRESHOLDS.CRITICAL;
  if (n >= VELOCITY_THRESHOLDS.HIGH.scans7d)     return VELOCITY_THRESHOLDS.HIGH;
  if (n >= VELOCITY_THRESHOLDS.MEDIUM.scans7d)   return VELOCITY_THRESHOLDS.MEDIUM;
  if (n >= VELOCITY_THRESHOLDS.LOW.scans7d)      return VELOCITY_THRESHOLDS.LOW;
  return VELOCITY_THRESHOLDS.CLEAN;
}

function buildEvidence(domain, counts, threshold) {
  const evidence = [];
  evidence.push(`Domain "${domain}" scanned ${counts['24h']} time(s) in last 24h`);
  evidence.push(`Domain "${domain}" scanned ${counts['7d']} time(s) in last 7 days`);
  evidence.push(`Domain "${domain}" scanned ${counts['30d']} time(s) in last 30 days`);
  if (threshold.label === 'CRITICAL') {
    evidence.push('CRITICAL: Scan frequency consistent with active phishing campaign');
  } else if (threshold.label === 'HIGH') {
    evidence.push('HIGH: Elevated scan frequency — domain likely under active investigation');
  } else if (threshold.label === 'MEDIUM') {
    evidence.push('MEDIUM: Moderate scan frequency — unusual security attention');
  } else if (threshold.label === 'LOW') {
    evidence.push('LOW: Slightly elevated scan count — monitor for escalation');
  } else {
    evidence.push('CLEAN: Scan frequency within normal range');
  }
  return evidence;
}

async function fetchDomainScans(domain) {
  const endpoint = `${API_ENDPOINTS.urlscanVelocity}/?q=${encodeURIComponent(`domain:${domain}`)}&size=100`;
  const response = await fetch(endpoint);
  if (!response.ok) {
    throw new Error(`URLScan search failed [${response.status}]`);
  }
  return response.json();
}

export async function checkVelocity(url) {
  const domain = extractDomain(url);
  try {
    const data = await fetchDomainScans(domain);
    const results = data.results ?? [];
    const timestamps = results
      .map(r => r?.task?.time)
      .filter(Boolean)
      .map(parseTimestamp)
      .filter(d => !isNaN(d));
    const counts    = bucketByWindow(timestamps);
    const threshold = scoreVelocity(counts);
    const evidence  = buildEvidence(domain, counts, threshold);
    return {
      signal:  'velocity',
      score:   threshold.score,
      verdict: threshold.label.toLowerCase(),
      evidence,
      counts,
      domain,
      error:   false,
    };
  } catch (err) {
    return {
      signal:   'velocity',
      score:    0,
      verdict:  'error',
      evidence: [`Velocity check failed: ${err.message}`],
      counts:   { '24h': 0, '7d': 0, '30d': 0, total: 0 },
      domain,
      error:    true,
      errorMsg: err.message,
    };
  }
}
