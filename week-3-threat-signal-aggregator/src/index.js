//=============================================
// index.js
// Main entry point for the Threat Signal
// Aggregator system
// This file orchestrates everything —
// it imports from every module and runs
// the complete detection pipeline
// No detection logic lives here
// This file only coordinates other modules
//=============================================

import "dotenv/config";

import { validateAPIKeys, validateBatch } from "./validators.js";
import { collectKeywordSignal } from "./signals/keywords.js";
import { collectURLScanSignal } from "./signals/urlscan.js";
import { collectGoogleSignal } from "./signals/google.js";
import { checkVelocity } from "./signals/velocity.js";
import { fuseSignals, buildErrorCase } from "./fusion.js";
import { printReport, printProgress } from "./reporter.js";
import { RATE_LIMITS } from "./config.js";

// ============================================
// SECTION 1 — STARTUP VALIDATION
// ============================================

const keyValidation = validateAPIKeys();

if (!keyValidation.valid) {
  console.log(`❌ ${keyValidation.error}`);
  process.exit(1);
}

console.log("✅ All systems operational");
console.log("✅ API keys validated");
console.log("✅ Threat Signal Aggregator v3.0 ready\n");

// ============================================
// SECTION 2 — SINGLE URL SCANNER
// ============================================

async function scanURL(url) {
  // Validate the URL format
  const { validateURL } = await import("./validators.js");
  const validation = validateURL(url);

  if (!validation.valid) {
    return buildErrorCase(url, validation.error);
  }

  // Collect keyword signal instantly
  const keywordSignal = collectKeywordSignal(url);

  // Collect API signals simultaneously
  const [urlscanSignal, googleSignal, velocitySignal] = await Promise.all([
  collectURLScanSignal(validation.hostname),
  collectGoogleSignal(url),
  checkVelocity(url),
]);

  // Fuse all signals into one verdict
  return fuseSignals(url, keywordSignal, urlscanSignal, googleSignal, velocitySignal);
}

// ============================================
// SECTION 3 — BATCH SCANNER
// ============================================

async function batchScan(urls) {
  // Validate the entire batch first
  const batchValidation = validateBatch(urls);

  if (!batchValidation.valid && batchValidation.validURLs.length === 0) {
    console.log(`❌ Batch validation failed: ${batchValidation.error}`);
    return [];
  }

  // Report any invalid URLs upfront
  if (batchValidation.invalidURLs.length > 0) {
    console.log(
      `⚠️  ${batchValidation.totalInvalid} invalid URL(s) skipped:`
    );
    batchValidation.invalidURLs.forEach((item) =>
      console.log(`   ${item.url} — ${item.reason}`)
    );
    console.log("");
  }

  const validURLs = batchValidation.validURLs;
  const results = [];

  console.log(`Starting scan of ${validURLs.length} valid URLs...\n`);

  for (let i = 0; i < validURLs.length; i++) {
    const url = validURLs[i];
    const result = await scanURL(url);
    results.push(result);

    printProgress(i + 1, validURLs.length, url, result.verdict);

    // Delay between URLs to respect rate limits
    if (i < validURLs.length - 1) {
      await new Promise((r) =>
        setTimeout(r, RATE_LIMITS.delayBetweenURLs)
      );
    }
  }

  return results;
}

// ============================================
// SECTION 4 — RUN
// ============================================

async function run() {
  console.log("=".repeat(52));
  console.log("   THREAT SIGNAL AGGREGATOR v3.0");
  console.log("=".repeat(52));
  console.log("Signals: Keywords + URLScan.io + Google Safe Browsing");
  console.log("=".repeat(52) + "\n");

  // Test batch including real threats from
  // previous weeks plus clean and invalid inputs
  const urlsToScan = [
    // Known threats from Week 2
    "https://htyd.vercel.app/",
    "https://instagrmm.vercel.app/",
    "https://interac-online.vercel.app/",
    "https://bank-sco.vercel.app/",

    // Keyword signals only
    "https://secure-login-verify.vercel.app/",
    "https://paypal-password-reset-account.vercel.app/",

    // Clean deployments
    "https://my-portfolio.vercel.app/",
    "https://johns-design-studio.vercel.app/",

    // Invalid inputs to test error handling
    "not-a-url",
    "",
    "ftp://wrong-protocol.com",
  ];

  const results = await batchScan(urlsToScan);
  printReport(results);
}

run();