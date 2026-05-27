// src/signals/sslAge.js
//
// SSL Certificate Age Signal
// ─────────────────────────────────────────────────────────────────────────────
// Opens a real TLS handshake to the target host and reads the certificate's
// notBefore date. No external API — uses Node's built-in tls module.
//
// Why this works where domain age fails:
// Every new deployment gets a fresh certificate regardless of how old the
// apex domain is. A phishing subdomain on vercel.app deployed today will
// have a cert issued today. vercel.app itself being 6 years old is irrelevant.
//
// Cert providers for free certs (Let's Encrypt, ZeroSSL) issue in seconds.
// A cert under 3 days old on a flagged domain = near-certain active attack.
// ─────────────────────────────────────────────────────────────────────────────

import tls from 'node:tls';

// ── Age thresholds (in days since cert was issued) ────────────────────────────

const CERT_AGE_THRESHOLDS = {
  CRITICAL: { maxDays: 3,   score: 90, label: 'CRITICAL' },
  HIGH:     { maxDays: 7,   score: 70, label: 'HIGH'     },
  MEDIUM:   { maxDays: 30,  score: 40, label: 'MEDIUM'   },
  LOW:      { maxDays: 90,  score: 15, label: 'LOW'      },
  CLEAN:    { maxDays: Infinity, score: 0, label: 'CLEAN' },
};

const TLS_TIMEOUT_MS = 8000;
const TLS_PORT = 443;

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractHostname(input) {
  try {
    const raw = input.startsWith('http') ? input : `https://${input}`;
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return input.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  }
}

function calcAgeDays(notBefore) {
  return Math.floor((Date.now() - new Date(notBefore).getTime()) / (1000 * 60 * 60 * 24));
}

function scoreAge(ageDays) {
  if (ageDays <= CERT_AGE_THRESHOLDS.CRITICAL.maxDays) return CERT_AGE_THRESHOLDS.CRITICAL;
  if (ageDays <= CERT_AGE_THRESHOLDS.HIGH.maxDays)     return CERT_AGE_THRESHOLDS.HIGH;
  if (ageDays <= CERT_AGE_THRESHOLDS.MEDIUM.maxDays)   return CERT_AGE_THRESHOLDS.MEDIUM;
  if (ageDays <= CERT_AGE_THRESHOLDS.LOW.maxDays)      return CERT_AGE_THRESHOLDS.LOW;
  return CERT_AGE_THRESHOLDS.CLEAN;
}

function buildEvidence(hostname, ageDays, notBefore, notAfter, issuer, threshold) {
  const evidence = [];

  evidence.push(`SSL cert issued: ${new Date(notBefore).toDateString()}`);
  evidence.push(`SSL cert expires: ${new Date(notAfter).toDateString()}`);
  evidence.push(`Cert age: ${ageDays} day(s)`);
  evidence.push(`Issuer: ${issuer}`);

  if (threshold.label === 'CRITICAL') {
    evidence.push('CRITICAL: Cert issued within last 3 days — fresh phishing infrastructure');
  } else if (threshold.label === 'HIGH') {
    evidence.push('HIGH: Cert under 7 days old — very recently deployed');
  } else if (threshold.label === 'MEDIUM') {
    evidence.push('MEDIUM: Cert under 30 days old — relatively new deployment');
  } else if (threshold.label === 'LOW') {
    evidence.push('LOW: Cert under 90 days old — worth noting alongside other signals');
  } else {
    evidence.push(`CLEAN: Cert is ${ageDays} days old — established deployment`);
  }

  return evidence;
}

// ── TLS Handshake ─────────────────────────────────────────────────────────────

/**
 * fetchCertInfo(hostname)
 *
 * Opens a TLS socket to hostname:443, reads the peer certificate,
 * closes the connection, and returns the raw cert object.
 * Rejects if connection fails or times out.
 */
function fetchCertInfo(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: TLS_PORT,
        servername: hostname,       // SNI — required for shared hosting / CDNs
        rejectUnauthorized: false,  // we want cert data even for self-signed
        timeout: TLS_TIMEOUT_MS,
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();

        if (!cert || Object.keys(cert).length === 0) {
          reject(new Error(`No certificate returned for ${hostname}`));
          return;
        }

        resolve(cert);
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`TLS connection timed out for ${hostname}`));
    });

    socket.on('error', (err) => {
      reject(new Error(`TLS connection failed for ${hostname}: ${err.message}`));
    });
  });
}

/**
 * Parse the issuer object from Node's tls cert into a readable string.
 * Node returns: { O: 'Let\'s Encrypt', CN: 'R11', C: 'US' }
 */
function parseIssuer(cert) {
  const i = cert.issuer ?? {};
  return i.O ?? i.CN ?? 'Unknown';
}

// ── Public Signal Function ────────────────────────────────────────────────────

/**
 * checkSSLAge(url)
 *
 * Matches the signal shape of all other signals in src/signals/.
 * Returns { signal, score, verdict, evidence, error } — never throws.
 */
export async function checkSSLAge(url) {
  const hostname = extractHostname(url);

  try {
    const cert = await fetchCertInfo(hostname);

    const notBefore = cert.valid_from;
    const notAfter  = cert.valid_to;

    if (!notBefore) {
      return {
        signal:   'sslAge',
        score:    0,
        verdict:  'unknown',
        evidence: [`SSL cert found but no issuance date available for "${hostname}"`],
        ageDays:  null,
        hostname,
        error:    false,
      };
    }

    const ageDays   = calcAgeDays(notBefore);
    const threshold = scoreAge(ageDays);
    const issuer    = parseIssuer(cert);
    const evidence  = buildEvidence(hostname, ageDays, notBefore, notAfter, issuer, threshold);

    return {
      signal:    'sslAge',
      score:     threshold.score,
      verdict:   threshold.label.toLowerCase(),
      evidence,
      ageDays,
      notBefore,
      notAfter,
      issuer,
      hostname,
      error:     false,
    };

  } catch (err) {
    return {
      signal:   'sslAge',
      score:    0,
      verdict:  'error',
      evidence: [`SSL age check failed: ${err.message}`],
      ageDays:  null,
      hostname,
      error:    true,
      errorMsg: err.message,
    };
  }
}

export { CERT_AGE_THRESHOLDS, extractHostname, calcAgeDays, scoreAge };