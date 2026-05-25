//=============================================
// fusion.js
// Signal fusion engine
// Takes all collected signals and combines
// them into one confident verdict
// This is the brain of the detection system
//=============================================

import {
  SIGNAL_WEIGHTS,
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
// Determines verdict tier from combined score

function calculateVerdict(score) {
  if (score >= VERDICT_THRESHOLDS.HIGH) return "HIGH";
  if (score >= VERDICT_THRESHOLDS.MEDIUM) return "MEDIUM";
  if (score >= VERDICT_THRESHOLDS.LOW) return "LOW";
  return "CLEAN";
}

// ============================================
// MAIN — FUSE SIGNALS
// ============================================

export function fuseSignals(url, keywordSignal, urlscanSignal, googleSignal) {
  let combinedScore = 0;
  let firedSignals = [];

  // Keyword contribution
  if (keywordSignal.score > 0) {
    const contribution =
      keywordSignal.score * SIGNAL_WEIGHTS.keywordScore;
    combinedScore += contribution;
    firedSignals.push(`keywords(+${contribution})`);
  }

  // URLScan malicious contribution
  if (urlscanSignal.malicious) {
    combinedScore += SIGNAL_WEIGHTS.urlscanMalicious;
    firedSignals.push(
      `urlscan_malicious(+${SIGNAL_WEIGHTS.urlscanMalicious})`
    );
  }

  // URLScan score contribution
  if (urlscanSignal.score > 0) {
    const contribution = Math.round(
      urlscanSignal.score * SIGNAL_WEIGHTS.urlscanScore
    );
    combinedScore += contribution;
    firedSignals.push(`urlscan_score(+${contribution})`);
  }

  // Google threat contribution
  if (googleSignal.threat) {
    combinedScore += SIGNAL_WEIGHTS.googleThreat;
    firedSignals.push(
      `google_threat(+${SIGNAL_WEIGHTS.googleThreat})`
    );
  }

  const verdict = calculateVerdict(combinedScore);

  return {
    caseId: generateCaseId(),
    url,
    combinedScore,
    verdict,
    action: ACTIONS[verdict],
    firedSignals,
    signalCount: firedSignals.length,
    signals: {
      keywords: keywordSignal,
      urlscan: urlscanSignal,
      google: googleSignal,
    },
    scannedAt: new Date().toISOString(),
  };
}

// ============================================
// ERROR CASE BUILDER
// ============================================
// Builds a structured result for URLs that
// failed validation or could not be scanned

export function buildErrorCase(url, error) {
  return {
    caseId: generateCaseId(),
    url,
    combinedScore: 0,
    verdict: "ERROR",
    action: ACTIONS.ERROR,
    firedSignals: [],
    signalCount: 0,
    error,
    signals: null,
    scannedAt: new Date().toISOString(),
  };
}

// ============================================
// BATCH SORTER
// ============================================
// Sorts a batch of fused results by priority
// Highest score first within each tier

export function sortByPriority(cases) {
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, CLEAN: 3, ERROR: 4 };

  return [...cases].sort((a, b) => {
    const tierDiff = order[a.verdict] - order[b.verdict];
    if (tierDiff !== 0) return tierDiff;
    return b.combinedScore - a.combinedScore;
  });
}