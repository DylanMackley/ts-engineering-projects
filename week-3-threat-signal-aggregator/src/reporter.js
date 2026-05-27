//=============================================
// reporter.js
// Report generation and formatting
// Takes fused case results and produces
// clean readable output for the terminal
// Also writes a structured JSON report file
// to reports/ after every scan
// In production this would feed a dashboard
// or case management system API
//=============================================

import fs from "node:fs";
import path from "node:path";
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
    flagRate:
      (
        (cases.filter(
          (c) => c.verdict === "HIGH" || c.verdict === "MEDIUM"
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

  console.log(`${emoji} #${index + 1} [${result.verdict}] ${result.url}`);
  console.log(`   Case ID:  ${result.caseId}`);
  console.log(`   Score:    ${result.combinedScore}`);
  console.log(`   Action:   ${result.action}`);
  console.log(`   Signals:  ${result.firedSignals.join(", ") || "none"}`);

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
    console.log(`   Keywords: ${result.signals.keywords.score} pts`);

    // Velocity signal line
    if (result.signals.velocity && !result.signals.velocity.error) {
      const v = result.signals.velocity;
      console.log(
        `   Velocity: ${v.counts["7d"]} scans/7d (${v.verdict})`
      );
    }

    // Domain age signal line
    if (result.signals.domainAge && !result.signals.domainAge.error) {
      const d = result.signals.domainAge;
      console.log(
        `   DomainAge: ${d.ageDays ?? "unknown"} days old (${d.verdict})`
      );
    }

    // SSL age signal line
    if (result.signals.sslAge && !result.signals.sslAge.error) {
      const s = result.signals.sslAge;
      console.log(
        `   SSLAge:   cert ${s.ageDays ?? "unknown"} days old — issued by ${s.issuer ?? "unknown"}`
      );
    }
  }

  if (result.error) {
    console.log(`   Error:    ${result.error}`);
  }

  console.log("");
}

// ============================================
// JSON REPORT BUILDER
// ============================================
// Structures all case data into a clean JSON
// object suitable for dashboards, CI, or
// portfolio display

function buildJSONReport(cases, summary) {
  return {
    meta: {
      tool:      "Threat Signal Aggregator",
      version:   "3.0",
      generatedAt: new Date().toISOString(),
      totalScanned: summary.total,
      flagRate:    summary.flagRate,
    },
    summary: {
      high:   summary.high,
      medium: summary.medium,
      low:    summary.low,
      clean:  summary.clean,
      errors: summary.errors,
    },
    signals: [
      "keywords",
      "urlscan",
      "google",
      "velocity",
      "domainAge",
      "sslAge",
    ],
    cases: cases.map((c) => ({
      caseId:       c.caseId,
      url:          c.url,
      verdict:      c.verdict,
      action:       c.action,
      combinedScore: c.combinedScore,
      firedSignals: c.firedSignals,
      scannedAt:    c.scannedAt,
      signals: {
        keywords: {
          score:    c.signals?.keywords?.score ?? 0,
          matched:  c.signals?.keywords?.matched ?? [],
        },
        urlscan: {
          malicious: c.signals?.urlscan?.malicious ?? false,
          score:     c.signals?.urlscan?.score ?? 0,
        },
        google: {
          threat:     c.signals?.google?.threat ?? false,
          threatType: c.signals?.google?.threatType ?? null,
        },
        velocity: {
          score:   c.signals?.velocity?.score ?? 0,
          verdict: c.signals?.velocity?.verdict ?? "error",
          counts:  c.signals?.velocity?.counts ?? null,
          error:   c.signals?.velocity?.error ?? true,
        },
        domainAge: {
          score:            c.signals?.domainAge?.score ?? 0,
          verdict:          c.signals?.domainAge?.verdict ?? "error",
          ageDays:          c.signals?.domainAge?.ageDays ?? null,
          registrationDate: c.signals?.domainAge?.registrationDate ?? null,
          error:            c.signals?.domainAge?.error ?? true,
        },
        sslAge: {
          score:     c.signals?.sslAge?.score ?? 0,
          verdict:   c.signals?.sslAge?.verdict ?? "error",
          ageDays:   c.signals?.sslAge?.ageDays ?? null,
          notBefore: c.signals?.sslAge?.notBefore ?? null,
          issuer:    c.signals?.sslAge?.issuer ?? null,
          error:     c.signals?.sslAge?.error ?? true,
        },
      },
    })),
  };
}

// ============================================
// JSON WRITER
// ============================================
// Writes the report to reports/ with a
// timestamp in the filename so every scan
// produces its own file — nothing overwrites

function writeJSONReport(report) {
  const reportsDir = path.resolve("reports");

  // Create reports/ if it doesn't exist
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
    errors.forEach((c) => console.log(`  ⚪ ${c.url} — ${c.error}`));
    console.log("");
  }

  // Footer
  console.log("=".repeat(52));
  console.log("END OF REPORT");
  console.log("=".repeat(52) + "\n");

  // ── JSON export ─────────────────────────────────────────────────────────
  const jsonReport = buildJSONReport(sorted, summary);
  const savedTo   = writeJSONReport(jsonReport);
  console.log(`📄 JSON report saved → ${savedTo}\n`);

  return summary;
}

// ============================================
// PROGRESS PRINTER
// ============================================
// Prints live progress during batch scanning
// so the user can see results as they come in

export function printProgress(current, total, url, verdict) {
  const emoji = EMOJI[verdict] ?? "⏳";
  console.log(`[${current}/${total}] ${emoji} ${verdict.padEnd(6)} — ${url}`);
}