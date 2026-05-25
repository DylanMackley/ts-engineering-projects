//=============================================
// reporter.js
// Report generation and formatting
// Takes fused case results and produces
// clean readable output for the terminal
// In production this would feed a dashboard
// or case management system API
//=============================================

import { sortByPriority } from "./fusion.js";

// ============================================
// VERDICT EMOJI MAP
// ============================================

const EMOJI = {
  HIGH: "🔴",
  MEDIUM: "🟡",
  LOW: "🟠",
  CLEAN: "🟢",
  ERROR: "⚪",
};

// ============================================
// SUMMARY BUILDER
// ============================================

function buildSummary(cases) {
  return {
    total: cases.length,
    high: cases.filter((c) => c.verdict === "HIGH").length,
    medium: cases.filter((c) => c.verdict === "MEDIUM").length,
    low: cases.filter((c) => c.verdict === "LOW").length,
    clean: cases.filter((c) => c.verdict === "CLEAN").length,
    errors: cases.filter((c) => c.verdict === "ERROR").length,
    flagRate: (
      (cases.filter((c) =>
        c.verdict === "HIGH" || c.verdict === "MEDIUM"
      ).length /
        cases.length) *
      100
    ).toFixed(1) + "%",
  };
}

// ============================================
// CASE PRINTER
// ============================================

function printCase(result, index) {
  const emoji = EMOJI[result.verdict];

  console.log(
    `${emoji} #${index + 1} [${result.verdict}] ${result.url}`
  );
  console.log(`   Case ID:  ${result.caseId}`);
  console.log(`   Score:    ${result.combinedScore}`);
  console.log(`   Action:   ${result.action}`);
  console.log(
    `   Signals:  ${result.firedSignals.join(", ") || "none"}`
  );

  if (result.signals) {
    console.log(
      `   Google:   ${
        result.signals.google.threat
          ? result.signals.google.threatType
          : "clean"
      }`
    );
    console.log(
      `   URLScan:  ${
        result.signals.urlscan.malicious ? "malicious" : "clean"
      } (score: ${result.signals.urlscan.score})`
    );
    console.log(
      `   Keywords: ${result.signals.keywords.score} pts`
    );
  }

  if (result.error) {
    console.log(`   Error:    ${result.error}`);
  }

  console.log("");
}

// ============================================
// MAIN — PRINT FULL REPORT
// ============================================

export function printReport(cases) {
  if (!cases || cases.length === 0) {
    console.log("No results to report");
    return;
  }

  const sorted = sortByPriority(cases);
  const summary = buildSummary(cases);

  // Header
  console.log("\n" + "=".repeat(52));
  console.log("   THREAT SIGNAL AGGREGATOR — TRIAGE REPORT");
  console.log("=".repeat(52));
  console.log(`Generated:     ${new Date().toISOString()}`);
  console.log(`Total Scanned: ${summary.total}`);
  console.log(`Flag Rate:     ${summary.flagRate}`);
  console.log("-".repeat(52));

  // Risk summary
  console.log("RISK SUMMARY");
  console.log(`  🔴 HIGH   — Auto Takedown:    ${summary.high}`);
  console.log(`  🟡 MEDIUM — Human Review:     ${summary.medium}`);
  console.log(`  🟠 LOW    — Monitor:          ${summary.low}`);
  console.log(`  🟢 CLEAN  — Clear:            ${summary.clean}`);
  console.log(`  ⚪ ERROR  — Invalid:          ${summary.errors}`);
  console.log("-".repeat(52));

  // Prioritized threat cases
  const threats = sorted.filter(
    (c) => c.verdict !== "CLEAN" && c.verdict !== "ERROR"
  );

  if (threats.length > 0) {
    console.log("\nPRIORITIZED CASES — Review In This Order:\n");
    threats.forEach((result, index) => printCase(result, index));
  } else {
    console.log("\n✅ No threats detected in this batch\n");
  }

  // Clean deployments
  const clean = sorted.filter((c) => c.verdict === "CLEAN");
  if (clean.length > 0) {
    console.log("-".repeat(52));
    console.log("\nCLEAN DEPLOYMENTS:");
    clean.forEach((c) => console.log(`  ✅ ${c.url}`));
    console.log("");
  }

  // Errors
  const errors = sorted.filter((c) => c.verdict === "ERROR");
  if (errors.length > 0) {
    console.log("-".repeat(52));
    console.log("\nINVALID INPUTS:");
    errors.forEach((c) =>
      console.log(`  ⚪ ${c.url} — ${c.error}`)
    );
    console.log("");
  }

  // Footer
  console.log("=".repeat(52));
  console.log("END OF REPORT");
  console.log("=".repeat(52) + "\n");

  return summary;
}

// ============================================
// PROGRESS PRINTER
// ============================================
// Prints live progress during batch scanning
// so the user can see results as they come in

export function printProgress(current, total, url, verdict) {
  const emoji = EMOJI[verdict] ?? "⏳";
  console.log(
    `[${current}/${total}] ${emoji} ${verdict.padEnd(6)} — ${url}`
  );
}