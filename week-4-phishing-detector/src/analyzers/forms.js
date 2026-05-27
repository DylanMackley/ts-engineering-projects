//=============================================
// analyzers/forms.js
// Detects suspicious form behavior
// Checks where forms submit to — if a form
// on vercel.app posts data to evil.com
// that is credential exfiltration
//=============================================

import { parse } from "node-html-parser";

// ============================================
// HELPERS
// ============================================

function extractHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function getPageHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// ============================================
// MAIN — ANALYZE FORMS
// ============================================

export function analyzeForms(html, pageURL) {
  const root        = parse(html);
  const forms       = root.querySelectorAll("form");
  const pageHost    = getPageHostname(pageURL);
  const findings    = [];
  let score         = 0;

  if (forms.length === 0) {
    return {
      analyzer: "forms",
      score:    0,
      verdict:  "clean",
      findings: ["No forms found on page"],
      formCount: 0,
      error:    false,
    };
  }

  for (const form of forms) {
    const action = form.getAttribute("action") ?? "";
    const method = (form.getAttribute("method") ?? "get").toLowerCase();

    // Check 1: form submits to external domain
    if (action.startsWith("http")) {
      const actionHost = extractHostname(action);
      if (actionHost && pageHost && actionHost !== pageHost) {
        score += 60;
        findings.push(
          `Form submits to external domain: ${actionHost} (page is ${pageHost})`
        );
      }
    }

    // Check 2: form uses POST — more likely harvesting credentials
    if (method === "post") {
      score += 10;
      findings.push(`Form uses POST method — action: "${action || "self"}"`);
    }

    // Check 3: form has no action — submits to current page (common in phishing)
    if (!action || action === "#" || action === "") {
      score += 15;
      findings.push("Form has no action attribute — submits to current page");
    }

    // Check 4: hidden fields (used to pass stolen data silently)
    const hiddenFields = form.querySelectorAll('input[type="hidden"]');
    if (hiddenFields.length > 3) {
      score += 20;
      findings.push(
        `Form contains ${hiddenFields.length} hidden fields — possible data exfiltration`
      );
    }
  }

  score = Math.min(score, 100);

  const verdict =
    score >= 70 ? "high" :
    score >= 40 ? "medium" :
    score >= 10 ? "low" : "clean";

  if (findings.length === 0) {
    findings.push(`${forms.length} form(s) found — no suspicious behavior detected`);
  }

  return {
    analyzer:  "forms",
    score,
    verdict,
    findings,
    formCount: forms.length,
    error:     false,
  };
}
