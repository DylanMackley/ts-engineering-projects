//=============================================
// Week 1 - Thursday
// Objective: Add error handling to every function
// T&S Use Case: A system processing real world
// data cannot crash on bad input. Every failure
// must be caught, named, and handled.
//=============================================

// --- CUSTOM ERROR CLASSES ---
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

// --- KEYWORDS (same as previous days) ---
const suspiciousKeywords = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "confirm",
  "password",
  "signin",
  "banking",
  "authentication",
];

// --- CHECKURL WITH ERROR HANDLING ---
// Updated version of Monday's function
// Now handles bad input instead of crashing

function checkURL(url) {
  try {
    // Check for null or undefined first
    if (url === null || url === undefined) {
      throw new InvalidURLError("URL cannot be null or undefined");
    }

    // Check that input is actually a string
    if (typeof url !== "string") {
      throw new InvalidURLError(`Expected a string but received ${typeof url}`);
    }

    // Check that string is not empty
    if (url.trim() === "") {
      throw new EmptyURLError("URL cannot be an empty string");
    }

    // Everything looks good - run the actual detection
    const lowercased = url.toLowerCase();
    let matches = [];

    for (let i = 0; i < suspiciousKeywords.length; i++) {
      if (lowercased.includes(suspiciousKeywords[i])) {
        matches.push(suspiciousKeywords[i]);
      }
    }

    return matches;
  } catch (error) {
    // Catch any error, log it clearly, return null
    // Returning null instead of crashing means the
    // rest of the system keeps running
    console.log(`[${error.name}] ${error.message}`);
    return null;
  }
}

// --- CREATEDEPLOYMENT FACTORY FUNCTION ---
// Copied from Wednesday - builds a structured
// deployment object from a URL and its matched keywords
// Now works with checkURL's null return on bad input

function createDeployment(url, matchedKeywords) {
  // If checkURL returned null due to an error
  // handle it here instead of crashing
  if (matchedKeywords === null) {
    return {
      url: url,
      reportedAt: new Date().toISOString(),
      matchedKeywords: [],
      matchCount: 0,
      riskLevel: "unknown",
      status: "scan_failed",
      getSummary: function () {
        return `[SCAN FAILED] ${this.url} could not be scanned`;
      },
    };
  }

  const matchCount = matchedKeywords.length;

  let riskLevel;
  if (matchCount >= 3) {
    riskLevel = "high";
  } else if (matchCount >= 1) {
    riskLevel = "medium";
  } else {
    riskLevel = "low";
  }

  return {
    url: url,
    reportedAt: new Date().toISOString(),
    matchedKeywords: matchedKeywords,
    matchCount: matchCount,
    riskLevel: riskLevel,
    status: "pending_review",
    getSummary: function () {
      return `[${this.riskLevel.toUpperCase()}] ${this.url} — ${this.matchCount} signal(s): ${this.matchedKeywords.join(", ") || "none"}`;
    },
  };
}

// --- BATCHSCAN WITH ERROR HANDLING ---
// Updated version of Tuesday's function
// Now protected against bad input at every step

function batchScan(urls) {
  try {
    // Check that input is actually an array
    if (!Array.isArray(urls)) {
      throw new InvalidBatchError(
        `Expected an array but received ${typeof urls}`,
      );
    }

    // Check that array is not empty
    if (urls.length === 0) {
      throw new EmptyBatchError("Cannot scan an empty array");
    }

    // Run every URL through checkURL then createDeployment
    const results = urls.map((url) => {
      const matchedKeywords = checkURL(url);
      return createDeployment(url, matchedKeywords);
    });

    // Separate into risk groups
    const suspicious = results.filter(
      (r) => r.riskLevel === "high" || r.riskLevel === "medium",
    );
    const clean = results.filter((r) => r.riskLevel === "low");
    const failed = results.filter((r) => r.riskLevel === "unknown");

    // Sort suspicious by matchCount highest first
    const prioritized = suspicious.sort((a, b) => b.matchCount - a.matchCount);

    // Build the full triage report
    const report = {
      totalScanned: urls.length,
      totalSuspicious: suspicious.length,
      totalClean: clean.length,
      totalFailed: failed.length,
      flagRate: ((suspicious.length / urls.length) * 100).toFixed(1) + "%",
      highestRisk: prioritized[0] || null,
      suspiciousURLs: prioritized,
      cleanURLs: clean,
      failedScans: failed,
    };

    return report;
  } catch (error) {
    console.log(`[${error.name}] ${error.message}`);
    return null;
  } finally {
    console.log(
      `Batch scan attempted on ${
        Array.isArray(urls) ? urls.length : "invalid"
      } items`,
    );
  }
}

// --- TEST BLOCK ---
// Testing bad inputs first to confirm error handling works
// Then testing good inputs to confirm detection still works

console.log("\n=== TESTING BAD INPUTS ===\n");

// These should all fail gracefully with named errors
console.log("Test null:");
console.log(checkURL(null));

console.log("\nTest number:");
console.log(checkURL(12345));

console.log("\nTest empty string:");
console.log(checkURL(""));

console.log("\nTest undefined:");
console.log(checkURL(undefined));

console.log("\nTest invalid batch - string instead of array:");
console.log(batchScan("not an array"));

console.log("\nTest invalid batch - empty array:");
console.log(batchScan([]));

console.log("\nTest invalid batch - null:");
console.log(batchScan(null));

console.log("\n=== TESTING GOOD INPUTS ===\n");

// These should work perfectly
console.log("Single URL scan:");
console.log(checkURL("signin-apple-id-locked.vercel.app"));

console.log("\nBatch scan:");
const testBatch = [
  "secure-login-verify.vercel.app",
  "my-portfolio.vercel.app",
  "account-update-banking.vercel.app",
  "paypal-confirm-identity.vercel.app",
  "creative-agency-2024.vercel.app",
];

const report = batchScan(testBatch);

console.log("\n--- TRIAGE REPORT ---");
console.log("Total Scanned:", report.totalScanned);
console.log("Total Suspicious:", report.totalSuspicious);
console.log("Total Clean:", report.totalClean);
console.log("Total Failed:", report.totalFailed);
console.log("Flag Rate:", report.flagRate);
console.log("\nHighest Risk URL:");
console.log(report.highestRisk.getSummary());
console.log("\nAll Suspicious URLs:");
report.suspiciousURLs.forEach((d) => console.log(d.getSummary()));
console.log("\nClean URLs:");
report.cleanURLs.forEach((d) => console.log(d.getSummary()));
