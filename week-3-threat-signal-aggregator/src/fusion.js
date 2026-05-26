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

function generateCaseId() {
  return `CASE-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

function calculateVerdict(score) {
  if (score >= VERDICT_THRESHOLDS.HIGH) return "HIGH";
  if (score >= VERDICT_THRESHOLDS.MEDIUM) return "MEDIUM";
  if (score >= VERDICT_THRESHOLDS.LOW) return "LOW";
  return "CLEAN";
}

export function fuseSignals(url, keywordSignal, urlscanSignal, googleSignal, velocitySignal) {
  let combinedScore = 0;
  let firedSignals = [];

  if (keywordSignal.score > 0) {
    const contribution = keywordSignal.score * SIGNAL_WEIGHTS.keywordScore;
    combinedScore += contribution;
    firedSignals.push(`keywords(+${contribution})`);
  }

  if (urlscanSignal.malicious) {
    combinedScore += SIGNAL_WEIGHTS.urlscanMalicious;
    firedSignals.push(`urlscan_malicious(+${SIGNAL_WEIGHTS.urlscanMalicious})`);
  }

  if (urlscanSignal.score > 0) {
    const contribution = Math.round(urlscanSignal.score * SIGNAL_WEIGHTS.urlscanScore);
    combinedScore += contribution;
    firedSignals.push(`urlscan_score(+${contribution})`);
  }

  if (velocitySignal && !velocitySignal.error && velocitySignal.score > 0) {
    const contribution = Math.round(velocitySignal.score * SIGNAL_WEIGHTS.velocityScore);
    combinedScore += contribution;
    firedSignals.push(`velocity(+${contribution})`);
  }

  if (googleSignal.threat) {
    combinedScore += SIGNAL_WEIGHTS.googleThreat;
    firedSignals.push(`google_threat(+${SIGNAL_WEIGHTS.googleThreat})`);
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
      velocity: velocitySignal ?? null,
    },
    scannedAt: new Date().toISOString(),
  };
}

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

export function sortByPriority(cases) {
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, CLEAN: 3, ERROR: 4 };
  return [...cases].sort((a, b) => {
    const tierDiff = order[a.verdict] - order[b.verdict];
    if (tierDiff !== 0) return tierDiff;
    return b.combinedScore - a.combinedScore;
  });
}
