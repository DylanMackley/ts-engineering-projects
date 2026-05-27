//=============================================
// reporter.js
// Report generation for Week 4
// Phishing Detector
//=============================================

import fs from "node:fs";
import path from "node:path";
import { sortByPriority } from "./fusion.js";

// ============================================
// VERDICT EMOJI MAP
// ============================================

const EMOJI = {
  HIGH:   "🔴",
  MEDIUM: "🟡",
  LOW:    "🟠",
  CLEAN:  "🟢",
  ERROR:  "⚪",
};

// ============================================
// SUMMARY BUILDER
// ============================================

function buildSummary(cases) {
  return {
    total:  cases.length,
    high:   cases.filter(c => c.verdict === "HIGH").length,
    medium: cases.filter(c => c.verdict === "MEDIUM").length,
    low:    cases.filter(c => c.verdict === "LOW").length,
    clean:  cases.filter(c => c.verdict === "CLEAN").length,
    errors: cases.filter(c => c.verdict === "ERROR").length,
    flagRate: (
      (cases.filter(c =>
        c.verdict === "HIGH" || c.verdict === "MEDIUM"
      ).length / cases.length) * 100
    ).toFixed(1) + "%",
  };
}

// ============================================
// CASE PRINTER
// ============================================

function printCase(result, index) {
  const emoji = EMOJI[result.verdict];
  console.log(`${emoji} #${index + 1} [${result.verdict}] ${result.url}`);
  console.log(`   Case ID:  ${result.caseId}`);
  console.log(`   Score:    ${result.combinedScore}`);
  console.log(`   Action:   ${result.action}`);
  console.log(`   Signals:  ${result.firedSignals.join(", ") || "none"}`);

  if (result.analyzers) {
    const { forms, brands, credentials, title } = result.analyzers;

    if (forms.findings?.length) {
      forms.findings.forEach(f => console.log(`   [forms]       ${f}`));
    }
    if (brands.findings?.length) {
      brands.findings.forEach(f => console.log(`   [brands]      ${f}`));
    }
    if (credentials.findings?.length) {
      credentials.findings.forEach(f => console.log(`   [credentials] ${f}`));
    }
    if (title.findings?.length) {
      title.findings.forEach(f => console.log(`   [title]       ${f}`));
    }
  }

  if (result.error) {
    console.log(`   Error: ${result.error}`);
  }

  console.log("");
}

// ============================================
// JSON WRITER
// ============================================

function writeJSONReport(report) {
  const reportsDir = path.resolve("reports");
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  const timestamp = new Date()
    .toISOString()
    .replace(/:/g, "-")
    .replace(/\..+/, "");

  const filename = path.join(reportsDir, `report-${timestamp}.json`);
  fs.writeFileSync(filename, JSON.stringify(report, null, 2), "utf-8");
  return filename;
}

// ============================================
// MAIN — PRINT FULL REPORT
// ============================================

export function printReport(cases) {
  if (!cases || cases.length === 0) {
    console.log("No results to report");
    return;
  }

  const sorted  = sortByPriority(cases);
  const summary = buildSummary(cases);

  console.log("\n" + "=".repeat(52));
  console.log("   PHISHING DETECTOR — TRIAGE REPORT");
  console.log("=".repeat(52));
  console.log(`Generated:     ${new Date().toISOString()}`);
  console.log(`Total Scanned: ${summary.total}`);
  console.log(`Flag Rate:     ${summary.flagRate}`);
  console.log("-".repeat(52));

  console.log("RISK SUMMARY");
  console.log(`  🔴 HIGH   — Auto Takedown:    ${summary.high}`);
  console.log(`  🟡 MEDIUM — Human Review:     ${summary.medium}`);
  console.log(`  🟠 LOW    — Monitor:          ${summary.low}`);
  console.log(`  🟢 CLEAN  — Clear:            ${summary.clean}`);
  console.log(`  ⚪ ERROR  — Invalid:          ${summary.errors}`);
  console.log("-".repeat(52));

  const threats = sorted.filter(
    c => c.verdict !== "CLEAN" && c.verdict !== "ERROR"
  );

  if (threats.length > 0) {
    console.log("\nPRIORITIZED CASES — Review In This Order:\n");
    threats.forEach((result, index) => printCase(result, index));
  } else {
    console.log("\n✅ No threats detected in this batch\n");
  }

  const clean = sorted.filter(c => c.verdict === "CLEAN");
  if (clean.length > 0) {
    console.log("-".repeat(52));
    console.log("\nCLEAN DEPLOYMENTS:");
    clean.forEach(c => console.log(`  ✅ ${c.url}`));
    console.log("");
  }

  const errors = sorted.filter(c => c.verdict === "ERROR");
  if (errors.length > 0) {
    console.log("-".repeat(52));
    console.log("\nFAILED SCANS:");
    errors.forEach(c => console.log(`  ⚪ ${c.url} — ${c.error}`));
    console.log("");
  }

  console.log("=".repeat(52));
  console.log("END OF REPORT");
  console.log("=".repeat(52) + "\n");

  const jsonReport = {
    meta: {
      tool:        "Phishing Detector",
      version:     "4.0",
      generatedAt: new Date().toISOString(),
    },
    summary,
    cases: sorted,
  };

  const savedTo = writeJSONReport(jsonReport);
  console.log(`📄 JSON report saved → ${savedTo}\n`);

  return summary;
}

// ============================================
// PROGRESS PRINTER
// ============================================

export function printProgress(current, total, url, verdict) {
  const emoji = EMOJI[verdict] ?? "⏳";
  console.log(`[${current}/${total}] ${emoji} ${verdict.padEnd(6)} — ${url}`);
}
