//=============================================
// Week 2 - Friday
// DEPLOYMENT SCANNER — Complete Build
//
// A production-quality multi-signal URL scanner
// that combines three independent threat sources:
//
// Signal 1: Keyword scoring (Week 1 logic)
// Signal 2: URLScan.io real-time scanning
// Signal 3: Google Safe Browsing database
//
// T&S Use Case: Automated first-pass detection
// of malicious deployments on hosting platforms.
// Produces prioritized triage reports with
// recommended enforcement actions.
//
// Built for infrastructure T&S teams dealing
// with phishing, brand impersonation, and
// credential harvesting on their platforms.
//=============================================

require("dotenv").config();

// ============================================
// SECTION 1 — ENVIRONMENT VALIDATION
// ============================================

const URLSCAN_KEY = process.env.URLSCAN_API_KEY;
const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

if (!URLSCAN_KEY || !GOOGLE_KEY) {
  console.log("❌ Missing API keys — check your .env file");
  process.exit(1);
}

// ============================================
// SECTION 2 — CONFIGURATION
// ============================================

const CONFIG = {
  keywords: {
    login: 10, verify: 10, secure: 8,
    account: 8, update: 7, confirm: 9,
    password: 15, signin: 10, banking: 12,
    authentication: 8,
  },
  signalWeights: {
    googleThreat: 50,
    urlscanMalicious: 45,
    urlscanScore: 0.3,
    keywordScore: 1,
  },
  thresholds: {
    HIGH: 70,
    MEDIUM: 40,
    LOW: 10,
  },
  actions: {
    HIGH: "AUTO TAKEDOWN",
    MEDIUM: "ESCALATE TO HUMAN REVIEW",
    LOW: "MONITOR",
    CLEAN: "CLEAR",
  },
  rateLimit: {
    delayBetweenURLs: 1500,
    delayBetweenAPICalls: 500,
  },
};

// ============================================
// SECTION 3 — INPUT VALIDATION
// ============================================

function validateURL(url) {
  if (!url || typeof url !== "string") {
    return { valid: false, error: "URL must be a non-empty string" };
  }

  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return { valid: false, error: "URL must use http or https" };
    }
    return { valid: true, parsed };
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }
}

// ============================================
// SECTION 4 — SIGNAL COLLECTORS
// ============================================

function collectKeywordSignal(url) {
  const lowercased = url.toLowerCase();
  let score = 0;
  let matched = [];

  for (const keyword in CONFIG.keywords) {
    if (lowercased.includes(keyword)) {
      score += CONFIG.keywords[keyword];
      matched.push({ keyword, points: CONFIG.keywords[keyword] });
    }
  }

  return { score, matched, fired: score > 0 };
}

async function collectURLScanSignal(hostname) {
  try {
    const searchRes = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${hostname}&size=3`,
      { headers: { "API-Key": URLSCAN_KEY } }
    );

    if (!searchRes.ok) return { fired: false, malicious: false, score: 0, tags: [] };

    const searchData = await searchRes.json();
    if (!searchData.results?.length) {
      return { fired: false, malicious: false, score: 0, tags: [], note: "no scans found" };
    }

    await new Promise((r) => setTimeout(r, CONFIG.rateLimit.delayBetweenAPICalls));

    const resultRes = await fetch(
      `https://urlscan.io/api/v1/result/${searchData.results[0]._id}/`,
      { headers: { "API-Key": URLSCAN_KEY } }
    );

    if (!resultRes.ok) return { fired: false, malicious: false, score: 0, tags: [] };

    const resultData = await resultRes.json();
    const malicious = resultData.verdicts?.overall?.malicious ?? false;
    const score = resultData.verdicts?.overall?.score ?? 0;
    const tags = resultData.verdicts?.overall?.tags ?? [];

    return { fired: malicious || score > 0, malicious, score, tags };

  } catch (error) {
    return { fired: false, malicious: false, score: 0, tags: [], error: error.message };
  }
}

async function collectGoogleSignal(url) {
  try {
    const body = {
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

    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );

    if (!res.ok) return { fired: false, threat: false, threatType: null };

    const data = await res.json();
    const match = data.matches?.[0];

    return {
      fired: !!match,
      threat: !!match,
      threatType: match?.threatType ?? null,
      platformType: match?.platformType ?? null,
    };

  } catch (error) {
    return { fired: false, threat: false, threatType: null, error: error.message };
  }
}

// ============================================
// SECTION 5 — SIGNAL FUSION
// ============================================

function fuseSignals(url, keyword, urlscan, google) {
  let score = 0;
  let firedSignals = [];

  if (keyword.score > 0) {
    const contribution = keyword.score * CONFIG.signalWeights.keywordScore;
    score += contribution;
    firedSignals.push(`keywords(+${contribution})`);
  }

  if (urlscan.malicious) {
    score += CONFIG.signalWeights.urlscanMalicious;
    firedSignals.push(`urlscan_malicious(+${CONFIG.signalWeights.urlscanMalicious})`);
  }

  if (urlscan.score > 0) {
    const contribution = Math.round(urlscan.score * CONFIG.signalWeights.urlscanScore);
    score += contribution;
    firedSignals.push(`urlscan_score(+${contribution})`);
  }

  if (google.threat) {
    score += CONFIG.signalWeights.googleThreat;
    firedSignals.push(`google_threat(+${CONFIG.signalWeights.googleThreat})`);
  }

  const verdict =
    score >= CONFIG.thresholds.HIGH ? "HIGH" :
    score >= CONFIG.thresholds.MEDIUM ? "MEDIUM" :
    score >= CONFIG.thresholds.LOW ? "LOW" : "CLEAN";

  return {
    caseId: `CASE-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    url,
    combinedScore: score,
    verdict,
    action: CONFIG.actions[verdict],
    firedSignals,
    signals: { keyword, urlscan, google },
    scannedAt: new Date().toISOString(),
  };
}

// ============================================
// SECTION 6 — MAIN SCANNER
// ============================================

async function scanURL(url) {
  const validation = validateURL(url);

  if (!validation.valid) {
    return {
      caseId: `CASE-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      url,
      verdict: "ERROR",
      action: "INVALID INPUT",
      error: validation.error,
      scannedAt: new Date().toISOString(),
    };
  }

  const hostname = validation.parsed.hostname;
  const keyword = collectKeywordSignal(url);
  const [urlscan, google] = await Promise.all([
    collectURLScanSignal(hostname),
    collectGoogleSignal(url),
  ]);

  return fuseSignals(url, keyword, urlscan, google);
}

async function batchScan(urls) {
  console.log(`\nStarting batch scan of ${urls.length} URLs...\n`);

  const results = [];

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    process.stdout.write(`[${i + 1}/${urls.length}] Scanning ${url}...`);

    const result = await scanURL(url);
    results.push(result);

    const emoji =
      result.verdict === "HIGH" ? "🔴" :
      result.verdict === "MEDIUM" ? "🟡" :
      result.verdict === "LOW" ? "🟠" :
      result.verdict === "ERROR" ? "⚪" : "🟢";

    console.log(` ${emoji} ${result.verdict}`);

    if (i < urls.length - 1) {
      await new Promise((r) => setTimeout(r, CONFIG.rateLimit.delayBetweenURLs));
    }
  }

  return results;
}

// ============================================
// SECTION 7 — REPORT GENERATOR
// ============================================

function generateReport(results) {
  const sorted = [...results].sort((a, b) => (b.combinedScore ?? 0) - (a.combinedScore ?? 0));

  const summary = {
    total: results.length,
    high: results.filter((r) => r.verdict === "HIGH").length,
    medium: results.filter((r) => r.verdict === "MEDIUM").length,
    low: results.filter((r) => r.verdict === "LOW").length,
    clean: results.filter((r) => r.verdict === "CLEAN").length,
    errors: results.filter((r) => r.verdict === "ERROR").length,
  };

  console.log("\n" + "=".repeat(50));
  console.log("   DEPLOYMENT SCANNER — TRIAGE REPORT");
  console.log("=".repeat(50));
  console.log(`Generated: ${new Date().toISOString()}`);
  console.log(`Total Scanned: ${summary.total}`);
  console.log("-".repeat(50));
  console.log("RISK SUMMARY");
  console.log(`  🔴 HIGH   — Auto Takedown:    ${summary.high}`);
  console.log(`  🟡 MEDIUM — Human Review:     ${summary.medium}`);
  console.log(`  🟠 LOW    — Monitor:          ${summary.low}`);
  console.log(`  🟢 CLEAN  — Clear:            ${summary.clean}`);
  console.log(`  ⚪ ERROR  — Invalid Input:    ${summary.errors}`);
  console.log("-".repeat(50));

  if (sorted.filter((r) => r.verdict !== "CLEAN" && r.verdict !== "ERROR").length > 0) {
    console.log("\nPRIORITIZED CASES:\n");

    sorted
      .filter((r) => r.verdict !== "CLEAN" && r.verdict !== "ERROR")
      .forEach((result, index) => {
        const emoji =
          result.verdict === "HIGH" ? "🔴" :
          result.verdict === "MEDIUM" ? "🟡" : "🟠";

        console.log(`${emoji} #${index + 1} [${result.verdict}] ${result.url}`);
        console.log(`   Case ID:  ${result.caseId}`);
        console.log(`   Score:    ${result.combinedScore}`);
        console.log(`   Action:   ${result.action}`);
        console.log(`   Signals:  ${result.firedSignals.join(", ") || "none"}`);
        console.log(`   Google:   ${result.signals.google.threat ? result.signals.google.threatType : "clean"}`);
        console.log(`   URLScan:  ${result.signals.urlscan.malicious ? "malicious" : "clean"} (score: ${result.signals.urlscan.score})`);
        console.log(`   Keywords: ${result.signals.keyword.score} pts`);
        console.log("");
      });
  }

  if (summary.clean > 0) {
    console.log("CLEAN DEPLOYMENTS:");
    sorted
      .filter((r) => r.verdict === "CLEAN")
      .forEach((r) => console.log(`  ✅ ${r.url}`));
    console.log("");
  }

  console.log("=".repeat(50));
  console.log("END OF REPORT");
  console.log("=".repeat(50) + "\n");

  return { summary, cases: sorted };
}

// ============================================
// SECTION 8 — RUN
// ============================================

async function run() {
  console.log("=".repeat(50));
  console.log("   DEPLOYMENT SCANNER v2.0");
  console.log("   Week 2 Complete Build");
  console.log("=".repeat(50));
  console.log("Signals: Keywords + URLScan.io + Google Safe Browsing");
  console.log("=".repeat(50));

  const urlsToScan = [
    "https://htyd.vercel.app/",
    "https://instagrmm.vercel.app/",
    "https://interac-online.vercel.app/",
    "https://my-portfolio.vercel.app/",
    "https://secure-login-verify.vercel.app/",
    "https://bank-sco.vercel.app/",
    "https://paypal-password-reset-account.vercel.app/",
  ];

  const results = await batchScan(urlsToScan);
  generateReport(results);
}

run();