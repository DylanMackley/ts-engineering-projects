//=============================================
// Week 2 - Thursday
// Objective: Combine all three signal sources
// into one unified multi-signal verdict system
// T&S Use Case: Real T&S systems never rely
// on one signal. Multi-signal fusion produces
// higher confidence verdicts with lower false
// positive rates than any single source alone.
//=============================================

require("dotenv").config();

const URLSCAN_KEY = process.env.URLSCAN_API_KEY;
const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

if (!URLSCAN_KEY || !GOOGLE_KEY) {
  console.log("❌ Missing API keys — check your .env file");
  process.exit(1);
}

console.log("✅ All API keys loaded\n");

// ============================================
// SECTION 1 — CONFIGURATION
// ============================================

const KEYWORD_WEIGHTS = {
  login: 10, verify: 10, secure: 8,
  account: 8, update: 7, confirm: 9,
  password: 15, signin: 10, banking: 12,
  authentication: 8,
};

const SIGNAL_WEIGHTS = {
  googleThreat: 50,
  urlscanMalicious: 45,
  urlscanScore: 0.3,
  keywordScore: 1,
};

const VERDICT_THRESHOLDS = {
  HIGH: 70,
  MEDIUM: 40,
  LOW: 10,
};

// ============================================
// SECTION 2 — KEYWORD SCANNER (from Week 1)
// ============================================

function keywordScan(url) {
  if (typeof url !== "string" || url.trim() === "") return { score: 0, signals: [] };

  const lowercased = url.toLowerCase();
  let score = 0;
  let signals = [];

  for (const keyword in KEYWORD_WEIGHTS) {
    if (lowercased.includes(keyword)) {
      score += KEYWORD_WEIGHTS[keyword];
      signals.push({ keyword, points: KEYWORD_WEIGHTS[keyword] });
    }
  }

  return { score, signals };
}

// ============================================
// SECTION 3 — URLSCAN SIGNAL
// ============================================

async function getURLScanSignal(url) {
  try {
    // Search for existing scans of this URL
    const domain = new URL(url).hostname;

    const searchResponse = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=3`,
      { headers: { "API-Key": URLSCAN_KEY } }
    );

    if (!searchResponse.ok) return { malicious: false, score: 0, tags: [] };

    const searchData = await searchResponse.json();

    if (!searchData.results || searchData.results.length === 0) {
      return { malicious: false, score: 0, tags: [], note: "no scans found" };
    }

    // Fetch verdict for most recent scan
    await new Promise((r) => setTimeout(r, 500));

    const resultResponse = await fetch(
      `https://urlscan.io/api/v1/result/${searchData.results[0]._id}/`,
      { headers: { "API-Key": URLSCAN_KEY } }
    );

    if (!resultResponse.ok) return { malicious: false, score: 0, tags: [] };

    const resultData = await resultResponse.json();

    return {
      malicious: resultData.verdicts?.overall?.malicious ?? false,
      score: resultData.verdicts?.overall?.score ?? 0,
      tags: resultData.verdicts?.overall?.tags ?? [],
    };

  } catch (error) {
    return { malicious: false, score: 0, tags: [], error: error.message };
  }
}

// ============================================
// SECTION 4 — GOOGLE SAFE BROWSING SIGNAL
// ============================================

async function getGoogleSignal(url) {
  try {
    const requestBody = {
      client: { clientId: "ts-engineering-projects", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    };

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      }
    );

    if (!response.ok) return { threat: false, threatType: null };

    const data = await response.json();

    if (!data.matches || data.matches.length === 0) {
      return { threat: false, threatType: null };
    }

    return {
      threat: true,
      threatType: data.matches[0].threatType,
      platformType: data.matches[0].platformType,
    };

  } catch (error) {
    return { threat: false, threatType: null, error: error.message };
  }
}

// ============================================
// SECTION 5 — SIGNAL FUSION ENGINE
// ============================================
// Takes all three signals and produces one
// combined confidence score and final verdict

function fuseSignals(url, keywordResult, urlscanResult, googleResult) {
  let combinedScore = 0;
  let firedSignals = [];

  // Add keyword contribution
  if (keywordResult.score > 0) {
    const keywordContribution = keywordResult.score * SIGNAL_WEIGHTS.keywordScore;
    combinedScore += keywordContribution;
    firedSignals.push(`keywords(+${keywordContribution})`);
  }

  // Add URLScan contribution
  if (urlscanResult.malicious) {
    combinedScore += SIGNAL_WEIGHTS.urlscanMalicious;
    firedSignals.push(`urlscan_malicious(+${SIGNAL_WEIGHTS.urlscanMalicious})`);
  }

  if (urlscanResult.score > 0) {
    const urlscanContribution = Math.round(urlscanResult.score * SIGNAL_WEIGHTS.urlscanScore);
    combinedScore += urlscanContribution;
    firedSignals.push(`urlscan_score(+${urlscanContribution})`);
  }

  // Add Google contribution
  if (googleResult.threat) {
    combinedScore += SIGNAL_WEIGHTS.googleThreat;
    firedSignals.push(`google_threat(+${SIGNAL_WEIGHTS.googleThreat})`);
  }

  // Determine verdict from combined score
  let verdict;
  let action;

  if (combinedScore >= VERDICT_THRESHOLDS.HIGH) {
    verdict = "HIGH";
    action = "AUTO TAKEDOWN";
  } else if (combinedScore >= VERDICT_THRESHOLDS.MEDIUM) {
    verdict = "MEDIUM";
    action = "ESCALATE TO HUMAN REVIEW";
  } else if (combinedScore >= VERDICT_THRESHOLDS.LOW) {
    verdict = "LOW";
    action = "MONITOR";
  } else {
    verdict = "CLEAN";
    action = "CLEAR";
  }

  return {
    url,
    combinedScore,
    verdict,
    action,
    firedSignals,
    signals: {
      keywords: keywordResult,
      urlscan: urlscanResult,
      google: googleResult,
    },
  };
}

// ============================================
// SECTION 6 — MAIN SCANNER
// ============================================

async function scanURL(url) {
  console.log(`Scanning: ${url}`);

  // Run keyword scan immediately (no API call needed)
  const keywordResult = keywordScan(url);

  // Run both API signals simultaneously
  const [urlscanResult, googleResult] = await Promise.all([
    getURLScanSignal(url),
    getGoogleSignal(url),
  ]);

  // Fuse all signals into one verdict
  return fuseSignals(url, keywordResult, urlscanResult, googleResult);
}

// ============================================
// SECTION 7 — RUN AND DISPLAY
// ============================================

async function run() {
  const urlsToScan = [
    "https://htyd.vercel.app/",
    "https://instagrmm.vercel.app/",
    "https://interac-online.vercel.app/",
    "https://my-portfolio.vercel.app/",
    "https://secure-login-verify.vercel.app/",
  ];

  console.log("============================================");
  console.log("   MULTI-SIGNAL DETECTION SYSTEM");
  console.log("============================================\n");

  const results = [];

  for (const url of urlsToScan) {
    const result = await scanURL(url);
    results.push(result);
    await new Promise((r) => setTimeout(r, 1000));
    console.log("");
  }

  // Display full report
  console.log("\n============================================");
  console.log("   TRIAGE REPORT — MULTI-SIGNAL VERDICTS");
  console.log("============================================\n");

  // Sort by combined score highest first
  results
    .sort((a, b) => b.combinedScore - a.combinedScore)
    .forEach((result, index) => {
      const emoji =
        result.verdict === "HIGH" ? "🔴" :
        result.verdict === "MEDIUM" ? "🟡" :
        result.verdict === "LOW" ? "🟠" : "🟢";

      console.log(`#${index + 1} ${emoji} ${result.verdict} — ${result.url}`);
      console.log(`   Score:   ${result.combinedScore}`);
      console.log(`   Action:  ${result.action}`);
      console.log(`   Signals: ${result.firedSignals.join(", ") || "none"}`);
      console.log(`   Google:  ${result.signals.google.threat ? result.signals.google.threatType : "clean"}`);
      console.log(`   URLScan: ${result.signals.urlscan.malicious ? "malicious" : "clean"} (score: ${result.signals.urlscan.score})`);
      console.log(`   Keywords: ${result.signals.keywords.score} pts`);
      console.log("");
    });

  // Summary
  const high = results.filter((r) => r.verdict === "HIGH").length;
  const medium = results.filter((r) => r.verdict === "MEDIUM").length;
  const low = results.filter((r) => r.verdict === "LOW").length;
  const clean = results.filter((r) => r.verdict === "CLEAN").length;

  console.log("============================================");
  console.log("SUMMARY");
  console.log(`🔴 HIGH — Auto Takedown:      ${high}`);
  console.log(`🟡 MEDIUM — Human Review:     ${medium}`);
  console.log(`🟠 LOW — Monitor:             ${low}`);
  console.log(`🟢 CLEAN — Clear:             ${clean}`);
  console.log("============================================");
}

run();