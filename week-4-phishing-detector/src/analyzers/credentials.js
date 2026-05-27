//=============================================
// analyzers/credentials.js
// Detects credential harvesting patterns
// Looks for password fields, sensitive input
// names, and data collection patterns that
// indicate the page is stealing user data
//=============================================

import { parse } from "node-html-parser";
import { CREDENTIAL_KEYWORDS } from "../config.js";

// ============================================
// MAIN — ANALYZE CREDENTIALS
// ============================================

export function analyzeCredentials(html, pageURL) {
  const root     = parse(html);
  const findings = [];
  let score      = 0;

  // Check 1: password input fields
  const passwordFields = root.querySelectorAll('input[type="password"]');
  if (passwordFields.length > 0) {
    score += 40;
    findings.push(
      `${passwordFields.length} password input field(s) detected`
    );
  }

  // Check 2: input names containing credential keywords
  const allInputs = root.querySelectorAll("input");
  const suspiciousInputs = [];

  for (const input of allInputs) {
    const name        = (input.getAttribute("name")        ?? "").toLowerCase();
    const id          = (input.getAttribute("id")          ?? "").toLowerCase();
    const placeholder = (input.getAttribute("placeholder") ?? "").toLowerCase();

    for (const keyword of CREDENTIAL_KEYWORDS) {
      if (
        name.includes(keyword) ||
        id.includes(keyword) ||
        placeholder.includes(keyword)
      ) {
        suspiciousInputs.push({ keyword, name: name || id || placeholder });
        break;
      }
    }
  }

  if (suspiciousInputs.length > 0) {
    score += suspiciousInputs.length * 15;
    suspiciousInputs.forEach(({ keyword, name }) => {
      findings.push(
        `Credential keyword "${keyword}" found in input field "${name}"`
      );
    });
  }

  // Check 3: credit card fields (specific pattern)
  const ccFields = root.querySelectorAll(
    'input[name*="card"], input[name*="cc"], input[id*="card"]'
  );
  if (ccFields.length > 0) {
    score += 50;
    findings.push(
      `${ccFields.length} credit card input field(s) detected`
    );
  }

  // Check 4: multiple sensitive fields together
  // (password + card = almost certainly phishing)
  if (passwordFields.length > 0 && ccFields.length > 0) {
    score += 30;
    findings.push(
      "CRITICAL: Password and credit card fields on same page"
    );
  }

  score = Math.min(score, 100);

  const verdict =
    score >= 70 ? "high"   :
    score >= 40 ? "medium" :
    score >= 10 ? "low"    : "clean";

  if (findings.length === 0) {
    findings.push("No credential harvesting patterns detected");
  }

  return {
    analyzer:        "credentials",
    score,
    verdict,
    findings,
    passwordFields:  passwordFields.length,
    suspiciousInputs: suspiciousInputs.length,
    error:           false,
  };
}
