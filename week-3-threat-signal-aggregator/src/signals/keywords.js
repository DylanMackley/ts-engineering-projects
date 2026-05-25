//=============================================
// signals/keywords.js
// Keyword signal collector
// Scans URLs for weighted phishing keywords
// First signal layer — no API calls needed
// Instant results with zero rate limit risk
//=============================================

import { KEYWORD_WEIGHTS } from "../config.js";

// ============================================
// KEYWORD SIGNAL COLLECTOR
// ============================================

export function collectKeywordSignal(url) {
  const lowercased = url.toLowerCase();
  let score = 0;
  let matched = [];

  for (const keyword in KEYWORD_WEIGHTS) {
    if (lowercased.includes(keyword)) {
      score += KEYWORD_WEIGHTS[keyword];
      matched.push({
        keyword,
        points: KEYWORD_WEIGHTS[keyword],
      });
    }
  }

  return {
    signal: "keywords",
    fired: score > 0,
    score,
    matched,
    summary:
      score > 0
        ? `${matched.length} keyword(s) matched — ${score} pts`
        : "no keywords matched",
  };
}

// ============================================
// KEYWORD BATCH SCANNER
// ============================================
// Scans a list of URLs and returns results
// sorted by score highest first

export function batchKeywordScan(urls) {
  const results = urls.map((url) => ({
    url,
    ...collectKeywordSignal(url),
  }));

  return results.sort((a, b) => b.score - a.score);
}