//=============================================
// analyzers/title.js
// Detects brand impersonation in page title
// Phishing pages often copy the exact title
// of the legitimate site they are faking
// e.g. "PayPal - Log in to your account"
// on a domain that is not paypal.com
//=============================================

import { parse } from "node-html-parser";
import { KNOWN_BRANDS } from "../config.js";

// ============================================
// HELPERS
// ============================================

function getPageHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// ============================================
// MAIN — ANALYZE TITLE
// ============================================

export function analyzeTitle(html, pageURL) {
  const root     = parse(html);
  const pageHost = getPageHostname(pageURL);
  const findings = [];
  let score      = 0;

  // Get page title
  const titleEl = root.querySelector("title");
  const title   = titleEl?.text?.trim() ?? "";

  if (!title) {
    return {
      analyzer: "title",
      score:    10,
      verdict:  "low",
      findings: ["Page has no title tag — suspicious for a legitimate site"],
      title:    null,
      error:    false,
    };
  }

  const titleLower = title.toLowerCase();

  // Check each known brand against the title
  for (const [brand, legitimateDomain] of Object.entries(KNOWN_BRANDS)) {
    if (!titleLower.includes(brand.toLowerCase())) continue;

    const isLegitimate = pageHost &&
      (pageHost === legitimateDomain ||
       pageHost.endsWith(`.${legitimateDomain}`));

    if (!isLegitimate) {
      score += 60;
      findings.push(
        `Title "${title}" references brand "${brand}" but domain is "${pageHost}"`
      );
    }
  }

  // Check for login/verify/secure language in title
  const suspiciousTitleWords = [
    "login", "log in", "sign in", "verify",
    "confirm", "secure", "update", "validate",
  ];

  for (const word of suspiciousTitleWords) {
    if (titleLower.includes(word)) {
      score += 10;
      findings.push(`Title contains suspicious word: "${word}"`);
      break;
    }
  }

  score = Math.min(score, 100);

  const verdict =
    score >= 70 ? "high"   :
    score >= 40 ? "medium" :
    score >= 10 ? "low"    : "clean";

  if (findings.length === 0) {
    findings.push(`Title "${title}" — no suspicious patterns detected`);
  }

  return {
    analyzer: "title",
    score,
    verdict,
    findings,
    title,
    error:    false,
  };
}
