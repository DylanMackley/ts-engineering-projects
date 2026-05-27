//=============================================
// fusion.js
// Signal fusion engine for Week 4
// Combines all 4 analyzer scores into one
// confident verdict
//=============================================

import {
  ANALYZER_WEIGHTS,
  VERDICT_THRESHOLDS,
  ACTIONS,
} from "./config.js";

// ============================================
// CASE ID GENERATOR
// ============================================

function generateCaseId() {
  return `CASE-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

// ============================================
// VERDICT CALCULATOR
// ============================================

function calculateVerdict(score) {
  if (score >= VERDICT_THRESHOLDS.HIGH)   return "HIGH";
  if (score >= VERDICT_THRESHOLDS.MEDIUM) return "MEDIUM";
  if (score >= VERDICT_THRESHOLDS.LOW)    return "LOW";
  return "CLEAN";
}

// ============================================
// MAIN — FUSE ANALYZERS
// ============================================

export function fuseAnalyzers(url, formsResult, brandsResult, credentialsResult, titleResult) {
  let combinedScore = 0;
  let firedSignals  = [];

  // Forms contribution
  if (formsResult.score > 0) {
    const contribution = Math.round(
      formsResult.score * ANALYZER_WEIGHTS.forms
    );
    combinedScore += contribution;
    firedSignals.push(`forms(+${contribution})`);
  }

  // Brands contribution
  if (brandsResult.score > 0) {
    const contribution = Math.round(
      brandsResult.score * ANALYZER_WEIGHTS.brands
    );
    combinedScore += contribution;
    firedSignals.push(`brands(+${contribution})`);
  }

  // Credentials contribution
  if (credentialsResult.score > 0) {
    const contribution = Math.round(
      credentialsResult.score * ANALYZER_WEIGHTS.credentials
    );
    combinedScore += contribution;
    firedSignals.push(`credentials(+${contribution})`);
  }

  // Title contribution
  if (titleResult.score > 0) {
    const contribution = Math.round(
      titleResult.score * ANALYZER_WEIGHTS.title
    );
    combinedScore += contribution;
    firedSignals.push(`title(+${contribution})`);
  }

  combinedScore = Math.min(combinedScore, 100);
  const verdict = calculateVerdict(combinedScore);

  return {
    caseId:       generateCaseId(),
    url,
    combinedScore,
    verdict,
    action:       ACTIONS[verdict],
    firedSignals,
    signalCount:  firedSignals.length,
    analyzers: {
      forms:       formsResult,
      brands:      brandsResult,
      credentials: credentialsResult,
      title:       titleResult,
    },
    scannedAt: new Date().toISOString(),
  };
}

// ============================================
// ERROR CASE BUILDER
// ============================================

export function buildErrorCase(url, error) {
  return {
    caseId:       generateCaseId(),
    url,
    combinedScore: 0,
    verdict:      "ERROR",
    action:       ACTIONS.ERROR,
    firedSignals: [],
    signalCount:  0,
    error,
    analyzers:    null,
    scannedAt:    new Date().toISOString(),
  };
}

// ============================================
// BATCH SORTER
// ============================================

export function sortByPriority(cases) {
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, CLEAN: 3, ERROR: 4 };
  return [...cases].sort((a, b) => {
    const tierDiff = order[a.verdict] - order[b.verdict];
    if (tierDiff !== 0) return tierDiff;
    return b.combinedScore - a.combinedScore;
  });
}
