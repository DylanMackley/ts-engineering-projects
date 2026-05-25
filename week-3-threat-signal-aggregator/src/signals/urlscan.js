//=============================================
// signals/urlscan.js
// URLScan.io signal collector
// Two-call pattern: search then fetch verdict
// Second signal layer — requires API key
//=============================================

import { API_ENDPOINTS, RATE_LIMITS } from "../config.js";

const URLSCAN_KEY = process.env.URLSCAN_API_KEY;

// ============================================
// HELPER — DELAY
// ============================================
// Pauses execution to respect API rate limits

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================
// CALL 1 — SEARCH
// ============================================

async function searchDomain(hostname) {
  try {
    const response = await fetch(
      `${API_ENDPOINTS.urlscanSearch}/?q=domain:${hostname}&size=3`,
      {
        headers: {
          "API-Key": URLSCAN_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Search failed — status ${response.status}`);
    }

    const data = await response.json();
    return data.results ?? [];

  } catch (error) {
    console.log(`[URLScan] Search failed: ${error.message}`);
    return [];
  }
}

// ============================================
// CALL 2 — FETCH VERDICT
// ============================================

async function fetchVerdict(scanId) {
  try {
    const response = await fetch(
      `${API_ENDPOINTS.urlscanResult}/${scanId}/`,
      {
        headers: {
          "API-Key": URLSCAN_KEY,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Verdict fetch failed — status ${response.status}`);
    }

    const data = await response.json();

    return {
      malicious: data.verdicts?.overall?.malicious ?? false,
      score: data.verdicts?.overall?.score ?? 0,
      tags: data.verdicts?.overall?.tags ?? [],
      categories: data.verdicts?.overall?.categories ?? [],
      screenshot: data.task?.screenshotURL ?? null,
    };

  } catch (error) {
    console.log(`[URLScan] Verdict fetch failed: ${error.message}`);
    return null;
  }
}

// ============================================
// MAIN — COLLECT URLSCAN SIGNAL
// ============================================

export async function collectURLScanSignal(hostname) {
  try {
    const scans = await searchDomain(hostname);

    if (scans.length === 0) {
      return {
        signal: "urlscan",
        fired: false,
        malicious: false,
        score: 0,
        tags: [],
        categories: [],
        screenshot: null,
        note: "no scans found for this domain",
      };
    }

    await delay(RATE_LIMITS.delayBetweenAPICalls);

    const verdict = await fetchVerdict(scans[0]._id);

    if (!verdict) {
      return {
        signal: "urlscan",
        fired: false,
        malicious: false,
        score: 0,
        tags: [],
        note: "verdict fetch failed",
      };
    }

    return {
      signal: "urlscan",
      fired: verdict.malicious || verdict.score > 0,
      malicious: verdict.malicious,
      score: verdict.score,
      tags: verdict.tags,
      categories: verdict.categories,
      screenshot: verdict.screenshot,
      summary: verdict.malicious
        ? `malicious — score ${verdict.score}`
        : `clean — score ${verdict.score}`,
    };

  } catch (error) {
    return {
      signal: "urlscan",
      fired: false,
      malicious: false,
      score: 0,
      tags: [],
      error: error.message,
    };
  }
}