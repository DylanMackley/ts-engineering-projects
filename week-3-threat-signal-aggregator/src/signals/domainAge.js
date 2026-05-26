// src/signals/domainAge.js
//
// Domain Age Signal
// ─────────────────────────────────────────────────────────────────────────────
// Checks how old a domain is using RDAP (Registration Data Access Protocol).
// RDAP is the modern replacement for WHOIS — free, no API key, JSON responses.
//
// Why domain age matters:
// Phishing campaigns register domains hours or days before launching attacks.
// A domain under 30 days old combined with any other signal is near-certain
// evidence of malicious intent. Legitimate businesses rarely deploy on
// brand-new domains.
//
// API: https://rdap.org/domain/{domain}
// No key required. Handles routing to the correct registry automatically.
// ─────────────────────────────────────────────────────────────────────────────

// ── Age thresholds (in days) ──────────────────────────────────────────────────
// Based on phishing campaign research — most attacks launch within 7 days
// of domain registration. 30 days is the outer edge of "suspicious new".

const AGE_THRESHOLDS = {
  CRITICAL: { maxDays: 7,   score: 90, label: 'CRITICAL' },
  HIGH:     { maxDays: 30,  score: 70, label: 'HIGH'     },
  MEDIUM:   { maxDays: 90,  score: 40, label: 'MEDIUM'   },
  LOW:      { maxDays: 180, score: 15, label: 'LOW'      },
  CLEAN:    { maxDays: Infinity, score: 0, label: 'CLEAN' },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractDomain(input) {
  try {
    const raw = input.startsWith('http') ? input : `https://${input}`;
    const hostname = new URL(raw).hostname.toLowerCase().replace(/^www\./, '');
    // RDAP only accepts apex domains — strip subdomains
    // e.g. htyd.vercel.app → vercel.app
    const parts = hostname.split('.');
    return parts.slice(-2).join('.');
  } catch {
    const hostname = input.replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
    const parts = hostname.split('.');
    return parts.slice(-2).join('.');
  }
}

/**
 * Calculate age in days from a registration date string to now.
 */
function calcAgeDays(registrationDateStr) {
  const registered = new Date(registrationDateStr);
  const now = new Date();
  return Math.floor((now - registered) / (1000 * 60 * 60 * 24));
}

/**
 * Score based on age in days.
 */
function scoreAge(ageDays) {
  if (ageDays <= AGE_THRESHOLDS.CRITICAL.maxDays) return AGE_THRESHOLDS.CRITICAL;
  if (ageDays <= AGE_THRESHOLDS.HIGH.maxDays)     return AGE_THRESHOLDS.HIGH;
  if (ageDays <= AGE_THRESHOLDS.MEDIUM.maxDays)   return AGE_THRESHOLDS.MEDIUM;
  if (ageDays <= AGE_THRESHOLDS.LOW.maxDays)      return AGE_THRESHOLDS.LOW;
  return AGE_THRESHOLDS.CLEAN;
}

/**
 * Pull the registration date out of an RDAP response.
 * RDAP returns an `events` array — we want eventAction === "registration".
 */
function extractRegistrationDate(rdapData) {
  const events = rdapData.events ?? [];
  const regEvent = events.find(e => e.eventAction === 'registration');
  return regEvent?.eventDate ?? null;
}

function buildEvidence(domain, ageDays, registrationDate, threshold) {
  const evidence = [];
  const regStr = registrationDate
    ? new Date(registrationDate).toDateString()
    : 'unknown';

  evidence.push(`Domain "${domain}" registered: ${regStr}`);
  evidence.push(`Domain age: ${ageDays} day(s)`);

  if (threshold.label === 'CRITICAL') {
    evidence.push('CRITICAL: Domain registered within last 7 days — extremely high risk');
  } else if (threshold.label === 'HIGH') {
    evidence.push('HIGH: Domain under 30 days old — consistent with fresh phishing infrastructure');
  } else if (threshold.label === 'MEDIUM') {
    evidence.push('MEDIUM: Domain under 90 days old — relatively new, warrants scrutiny');
  } else if (threshold.label === 'LOW') {
    evidence.push('LOW: Domain under 180 days old — slightly new but not conclusive');
  } else {
    evidence.push(`CLEAN: Domain is ${ageDays} days old — established domain`);
  }

  return evidence;
}

// ── RDAP Lookup ───────────────────────────────────────────────────────────────

async function fetchRDAP(domain) {
  const response = await fetch(`https://rdap.org/domain/${domain}`, {
    headers: { 'Accept': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`RDAP lookup failed [${response.status}] for ${domain}`);
  }

  return response.json();
}

// ── Public Signal Function ────────────────────────────────────────────────────

/**
 * checkDomainAge(url)
 *
 * Matches the signal shape of checkVelocity(), collectURLScanSignal(), etc.
 * Returns { signal, score, verdict, evidence, error } always — never throws.
 */
export async function checkDomainAge(url) {
  const domain = extractDomain(url);

  try {
    const rdapData = await fetchRDAP(domain);
    const registrationDate = extractRegistrationDate(rdapData);

    if (!registrationDate) {
      // RDAP responded but no registration event found — treat as unknown
      return {
        signal:   'domainAge',
        score:    0,
        verdict:  'unknown',
        evidence: [`Domain age unknown — no registration date in RDAP response for "${domain}"`],
        ageDays:  null,
        domain,
        error:    false,
      };
    }

    const ageDays   = calcAgeDays(registrationDate);
    const threshold = scoreAge(ageDays);
    const evidence  = buildEvidence(domain, ageDays, registrationDate, threshold);

    return {
      signal:           'domainAge',
      score:            threshold.score,
      verdict:          threshold.label.toLowerCase(),
      evidence,
      ageDays,
      registrationDate,
      domain,
      error:            false,
    };

  } catch (err) {
    return {
      signal:   'domainAge',
      score:    0,
      verdict:  'error',
      evidence: [`Domain age check failed: ${err.message}`],
      ageDays:  null,
      domain,
      error:    true,
      errorMsg: err.message,
    };
  }
}

export { AGE_THRESHOLDS, extractDomain, calcAgeDays, scoreAge };