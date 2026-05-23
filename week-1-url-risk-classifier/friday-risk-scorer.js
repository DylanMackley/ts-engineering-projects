//=============================================
// Week 1 - Friday
// URL Risk Scoring System
// 
// A complete phishing detection pipeline that:
// - Scans URLs for suspicious keyword signals
// - Assigns weighted risk scores
// - Builds structured deployment case files
// - Produces prioritized triage reports
// - Handles all errors gracefully
//
// T&S Use Case: Automated first-pass detection
// of malicious deployments on hosting platforms.
// Mirrors the core logic of real T&S detection
// systems at infrastructure companies like Vercel.
//
// Built by combining Monday through Thursday:
// Monday    → keyword detection
// Tuesday   → batch processing
// Wednesday → deployment objects
// Thursday  → error handling
//=============================================

// ============================================
// SECTION 1 — CUSTOM ERROR CLASSES
// ============================================

class InvalidURLError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidURLError";
  }
}

class EmptyURLError extends Error {
  constructor(message) {
    super(message);
    this.name = "EmptyURLError";
  }
}

class InvalidBatchError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidBatchError";
  }
}

class EmptyBatchError extends Error {
  constructor(message) {
    super(message);
    this.name = "EmptyBatchError";
  }
}

// ============================================
// SECTION 2 — CONFIGURATION
// ============================================
// Keyword weights represent how strongly each
// signal indicates a phishing attempt.
// Higher score = stronger phishing signal.
// These weights are based on common patterns
// seen in real deployment abuse campaigns.

const keywordWeights = {
  login: 10,
  verify: 10,
  secure: 8,
  account: 8,
  update: 7,
  confirm: 9,
  password: 15,
  signin: 10,
  banking: 12,
  authentication: 8,
};

// Risk thresholds — total score determines risk level
// Based on weighted signal combinations:
// password + banking alone = 27 points = MEDIUM
// login + verify + password = 35 points = HIGH
const RISK_THRESHOLDS = {
  HIGH: 20,
  MEDIUM: 10,
  LOW: 1,
};

// Pull keyword names into an array for scanning
const suspiciousKeywords = Object.keys(keywordWeights);

// ============================================
// SECTION 3 — CORE DETECTION FUNCTION
// ============================================
// Takes a single URL string, validates it,
// scans it against weighted keywords, and
// returns a score and list of matched signals.
// Returns null on invalid input without crashing.

function scanURL(url) {
  try {
    // Input validation
    if (url === null || url === undefined) {
      throw new InvalidURLError("URL cannot be null or undefined");
    }
    if (typeof url !== "string") {
      throw new InvalidURLError(
        `Expected a string but received ${typeof url}`
      );
    }
    if (url.trim() === "") {
      throw new EmptyURLError("URL cannot be an empty string");
    }

    const lowercased = url.toLowerCase();
    let totalScore = 0;
    let matchedSignals = [];

    // Check every keyword and add its weight to the score
    for (const keyword in keywordWeights) {
      if (lowercased.includes(keyword)) {
        totalScore += keywordWeights[keyword];
        matchedSignals.push({
          keyword: keyword,
          points: keywordWeights[keyword],
        });
      }
    }


    // Determine risk level from total score
    let riskLevel;
    if (totalScore >= RISK_THRESHOLDS.HIGH) {
      riskLevel = "high";
    } else if (totalScore >= RISK_THRESHOLDS.MEDIUM) {
      riskLevel = "medium";
    } else if (totalScore >= RISK_THRESHOLDS.LOW) {
      riskLevel = "low";
    } else {
      riskLevel = "clean";
    }

    return {
      url: url,
      totalScore: totalScore,
      riskLevel: riskLevel,
      matchedSignals: matchedSignals,
    };
  } catch (error) {
    console.log(`[${error.name}] ${error.message}`);
    return null;
  }
}

// ============================================
// SECTION 4 — DEPLOYMENT CASE BUILDER
// ============================================
// Takes a scan result and builds a structured
// deployment case file — the same concept used
// in real T&S case management systems.
// Every flagged deployment becomes a proper
// case with all relevant information attached.

function buildCase(scanResult) {
  // Handle failed scans from Section 3
  if (scanResult === null) {
    return {
      caseId: generateCaseId(),
      url: "unknown",
      reportedAt: new Date().toISOString(),
      totalScore: 0,
      riskLevel: "unknown",
      matchedSignals: [],
      status: "scan_failed",
      explanation: "Scan could not be completed due to invalid input",
      getSummary: function () {
        return `[SCAN FAILED] Case ${this.caseId} — could not be scanned`;
      },
      getSignalBreakdown: function () {
        return "No signals — scan failed";
      },
    };
  }

  return {
    caseId: generateCaseId(),
    url: scanResult.url,
    reportedAt: new Date().toISOString(),
    totalScore: scanResult.totalScore,
    riskLevel: scanResult.riskLevel,
    matchedSignals: scanResult.matchedSignals,
    status: scanResult.riskLevel === "clean" ? "cleared" : "pending_review",

    // Human readable summary of the case
    getSummary: function () {
      return `[${this.riskLevel.toUpperCase()}] ${this.url} — Score: ${this.totalScore} — Status: ${this.status}`;
    },

    // Breakdown of exactly which signals fired and why
    getSignalBreakdown: function () {
      if (this.matchedSignals.length === 0) {
        return `${this.url} — no suspicious signals detected`;
      }
      const signals = this.matchedSignals
        .map((s) => `${s.keyword}(+${s.points})`)
        .join(", ");
      return `${this.url} — signals: ${signals} — total: ${this.totalScore} pts`;
    },
  };
}

// Generates a simple unique case ID
// In a real system this would come from a database
function generateCaseId() {
  return "CASE-" + Date.now() + "-" + Math.floor(Math.random() * 1000);
}

// ============================================
// SECTION 5 — BATCH PROCESSING ENGINE
// ============================================
// Takes a list of URLs, runs each one through
// the full detection pipeline, and produces
// a complete prioritized triage report.
// This is the main engine of the system —
// everything above feeds into this function.

function runBatchScan(urls) {
  try {
    // Input validation
    if (!Array.isArray(urls)) {
      throw new InvalidBatchError(
        `Expected an array but received ${typeof urls}`
      );
    }
    if (urls.length === 0) {
      throw new EmptyBatchError("Cannot scan an empty array");
    }

    console.log(`\nScanning ${urls.length} URLs...\n`);

    // Run every URL through the full pipeline
    // scanURL → buildCase → structured case file
    const cases = urls.map((url) => {
      const scanResult = scanURL(url);
      return buildCase(scanResult);
    });

    // Separate into risk groups
    const highRisk = cases.filter((c) => c.riskLevel === "high");
    const mediumRisk = cases.filter((c) => c.riskLevel === "medium");
    const lowRisk = cases.filter((c) => c.riskLevel === "low");
    const clean = cases.filter((c) => c.riskLevel === "clean");
    const failed = cases.filter((c) => c.riskLevel === "unknown");

    // Sort high risk by score — highest first
    const prioritized = [...highRisk, ...mediumRisk].sort(
      (a, b) => b.totalScore - a.totalScore
    );

    // Build the complete triage report
    return {
      scannedAt: new Date().toISOString(),
      totalScanned: urls.length,
      summary: {
        high: highRisk.length,
        medium: mediumRisk.length,
        low: lowRisk.length,
        clean: clean.length,
        failed: failed.length,
      },
      flagRate: (
        ((highRisk.length + mediumRisk.length) / urls.length) *
        100
      ).toFixed(1) + "%",
      prioritizedCases: prioritized,
      cleanCases: clean,
      failedCases: failed,
    };
  } catch (error) {
    console.log(`[${error.name}] ${error.message}`);
    return null;
  } finally {
    console.log(
      `Batch scan attempted on ${
        Array.isArray(urls) ? urls.length : "invalid"
      } items`
    );
  }
}

// ============================================
// SECTION 6 — OUTPUT FORMATTER
// ============================================
// Takes a triage report and prints it in a
// clean readable format for the terminal.
// In a real system this would feed a dashboard
// or send data to a case management system.
// For now it formats everything for clear
// human readable output.

function printReport(report) {
  if (report === null) {
    console.log("No report to display — scan failed");
    return;
  }

  console.log("============================================");
  console.log("       PHISHING DETECTION TRIAGE REPORT    ");
  console.log("============================================");
  console.log(`Scanned At:        ${report.scannedAt}`);
  console.log(`Total Scanned:     ${report.totalScanned}`);
  console.log(`Flag Rate:         ${report.flagRate}`);
  console.log("--------------------------------------------");
  console.log("RISK SUMMARY");
  console.log(`  🔴 High Risk:    ${report.summary.high}`);
  console.log(`  🟡 Medium Risk:  ${report.summary.medium}`);
  console.log(`  🟢 Low Risk:     ${report.summary.low}`);
  console.log(`  ✅ Clean:        ${report.summary.clean}`);
  console.log(`  ⚪ Failed:       ${report.summary.failed}`);
  console.log("--------------------------------------------");

  if (report.prioritizedCases.length > 0) {
    console.log("\nPRIORITIZED CASES — Review In This Order:");
    console.log("--------------------------------------------");
    report.prioritizedCases.forEach((c, index) => {
      console.log(`\n#${index + 1} ${c.getSummary()}`);
      console.log(`    ${c.getSignalBreakdown()}`);
      console.log(`    Case ID: ${c.caseId}`);
    });
  } else {
    console.log("\nNo suspicious cases detected");
  }

  console.log("\n--------------------------------------------");

  if (report.cleanCases.length > 0) {
    console.log("\nCLEAN DEPLOYMENTS:");
    report.cleanCases.forEach((c) => {
      console.log(`  ✅ ${c.url}`);
    });
  }

  if (report.failedCases.length > 0) {
    console.log("\nFAILED SCANS — Requires Manual Review:");
    report.failedCases.forEach((c) => {
      console.log(`  ⚪ ${c.getSummary()}`);
    });
  }

  console.log("\n============================================");
  console.log("END OF REPORT");
  console.log("============================================\n");
}

// ============================================
// SECTION 7 — LIVE TEST RUN
// ============================================
// Demonstrates the complete system working
// end to end with realistic test data.
// Simulates a batch of deployments that might
// get flagged for review on a platform like
// Vercel in a real abuse campaign.
// ============================================

// --- TEST DATASET ---
// Mix of high risk, medium risk, clean, and
// invalid inputs to show the full system range

const testDeployments = [
  // High risk — multiple strong signals
  "secure-login-verify.vercel.app",
  "paypal-password-reset-account.vercel.app",
  "apple-id-signin-locked.vercel.app",

  // Medium risk — one or two signals
  "confirm-your-details.vercel.app",
  "banking-portal-2024.vercel.app",

  // Low risk — weak signals
  "update-log.vercel.app",

  // Clean — no signals
  "my-portfolio.vercel.app",
  "johns-design-studio.vercel.app",
  "creative-agency-2024.vercel.app",
  "restaurant-menu-site.vercel.app",

  // Invalid inputs — tests error handling
  "",
  null,
  12345,
];

// --- RUN THE FULL SYSTEM ---
console.log("\n============================================");
console.log("   PHISHING DETECTION SYSTEM — WEEK 1 BUILD");
console.log("============================================");
console.log("Initializing scan...");

// Step 1 — Run batch scan
const triageReport = runBatchScan(testDeployments);

// Step 2 — Print formatted report
printReport(triageReport);

// Step 3 — Demonstrate single URL scan
console.log("--- SINGLE URL SCAN DEMO ---\n");

const singleScan = buildCase(
  scanURL("paypal-password-reset-account.vercel.app")
);
console.log("Single scan result:");
console.log(singleScan.getSummary());
console.log(singleScan.getSignalBreakdown());
console.log("Case ID:", singleScan.caseId);

// Step 4 — Demonstrate error handling
console.log("\n--- ERROR HANDLING DEMO ---\n");

const badInputs = [null, 12345, "", undefined, []];
badInputs.forEach((input) => {
  console.log(`Input: ${JSON.stringify(input)}`);
  const result = scanURL(input);
  console.log(`Result: ${result}\n`);
});