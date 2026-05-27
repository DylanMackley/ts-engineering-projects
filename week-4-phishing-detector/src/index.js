//=============================================
// index.js
// Main entry point for the Phishing Detector
// Orchestrates fetching, analysis, fusion
// and reporting — no logic lives here
//=============================================

import "dotenv/config";
import fs from "node:fs";
import path from "node:path";

import { fetchPage }          from "./fetcher.js";
import { analyzeForms }       from "./analyzers/forms.js";
import { analyzeBrands }      from "./analyzers/brands.js";
import { analyzeCredentials } from "./analyzers/credentials.js";
import { analyzeTitle }       from "./analyzers/title.js";
import { fuseAnalyzers, buildErrorCase } from "./fusion.js";
import { printReport, printProgress }    from "./reporter.js";

// ============================================
// SECTION 1 — SINGLE URL SCANNER
// ============================================

async function scanURL(url, fixtureHTML = null) {
  let html;
  let finalURL = url;

  // Use fixture HTML if provided, otherwise fetch live
  if (fixtureHTML) {
    html = fixtureHTML;
  } else {
    const page = await fetchPage(url);
    if (!page.success) {
      return buildErrorCase(url, page.error);
    }
    html     = page.html;
    finalURL = page.finalURL;
  }

  const [formsResult, brandsResult, credentialsResult, titleResult] =
    await Promise.all([
      Promise.resolve(analyzeForms(html, finalURL)),
      Promise.resolve(analyzeBrands(html, finalURL)),
      Promise.resolve(analyzeCredentials(html, finalURL)),
      Promise.resolve(analyzeTitle(html, finalURL)),
    ]);

  return fuseAnalyzers(
    url,
    formsResult,
    brandsResult,
    credentialsResult,
    titleResult
  );
}

// ============================================
// SECTION 2 — BATCH SCANNER
// ============================================

async function batchScan(targets) {
  const results = [];

  console.log(`Starting scan of ${targets.length} URL(s)...\n`);

  for (let i = 0; i < targets.length; i++) {
    const { url, fixture } = targets[i];
    const html = fixture
      ? fs.readFileSync(path.resolve(fixture), "utf-8")
      : null;

    const result = await scanURL(url, html);
    results.push(result);

    printProgress(i + 1, targets.length, url, result.verdict);

    if (i < targets.length - 1) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  return results;
}

// ============================================
// SECTION 3 — RUN
// ============================================

async function run() {
  console.log("=".repeat(52));
  console.log("   PHISHING DETECTOR v4.0");
  console.log("=".repeat(52));
  console.log("Analyzers: Forms + Brands + Credentials + Title");
  console.log("=".repeat(52) + "\n");

  const targets = [
    // Fixture-based tests — simulated phishing pages
    {
      url:     "https://paypal-secure-login.vercel.app/",
      fixture: "src/fixtures/fake-paypal.html",
    },
    {
      url:     "https://interac-verify-account.vercel.app/",
      fixture: "src/fixtures/fake-interac.html",
    },
    {
      url:     "https://jane-smith-portfolio.vercel.app/",
      fixture: "src/fixtures/clean-portfolio.html",
    },
    // Live URL test
    {
      url:     "https://my-portfolio.vercel.app/",
      fixture: null,
    },
  ];

  const results = await batchScan(targets);
  printReport(results);
}

run();
