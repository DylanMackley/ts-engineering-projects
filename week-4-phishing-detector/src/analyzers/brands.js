//=============================================
// analyzers/brands.js
// Detects brand impersonation
// If a page mentions PayPal but is not on
// paypal.com — that is brand impersonation
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

function extractPageText(root) {
  // Get visible text — title, headings, paragraphs, buttons, labels
  const selectors = ["title", "h1", "h2", "h3", "p", "button", "label", "a"];
  return selectors
    .flatMap(sel => root.querySelectorAll(sel))
    .map(el => el.text.toLowerCase())
    .join(" ");
}

// ============================================
// MAIN — ANALYZE BRANDS
// ============================================

export function analyzeBrands(html, pageURL) {
  const root     = parse(html);
  const pageHost = getPageHostname(pageURL);
  const pageText = extractPageText(root);
  const findings = [];
  let score      = 0;

  const impersonated = [];

  for (const [brand, legitimateDomain] of Object.entries(KNOWN_BRANDS)) {
    // Check if brand name appears in page text
    if (!pageText.includes(brand.toLowerCase())) continue;

    // Check if page is actually on the legitimate domain
    const isLegitimate = pageHost &&
      (pageHost === legitimateDomain ||
       pageHost.endsWith(`.${legitimateDomain}`));

    if (!isLegitimate) {
      impersonated.push(brand);
      score += 50;
      findings.push(
        `Brand "${brand}" detected on page but domain is "${pageHost}" not "${legitimateDomain}"`
      );
    }
  }

  // Multiple brand impersonation is worse
  if (impersonated.length > 1) {
    score += 20;
    findings.push(
      `Multiple brands impersonated: ${impersonated.join(", ")}`
    );
  }

  score = Math.min(score, 100);

  const verdict =
    score >= 70 ? "high" :
    score >= 40 ? "medium" :
    score >= 10 ? "low" : "clean";

  if (findings.length === 0) {
    findings.push("No brand impersonation detected");
  }

  return {
    analyzer:    "brands",
    score,
    verdict,
    findings,
    impersonated,
    error:       false,
  };
}
