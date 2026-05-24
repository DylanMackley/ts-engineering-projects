//=============================================
// Week 2 - Tuesday
// Objective: Two-call pattern to get full
// verdict data from URLScan.io
// T&S Use Case: Automated verdict retrieval
// for real deployments on Vercel infrastructure
//=============================================

require("dotenv").config();

const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

if (!URLSCAN_API_KEY) {
  console.log("❌ URLSCAN_API_KEY not found");
  process.exit(1);
}

console.log("✅ API key loaded\n");

// ============================================
// CALL 1 — SEARCH FOR RECENT SCANS
// ============================================
// Searches URLScan.io for recent scans matching
// a domain and returns basic scan metadata
// including the scan ID needed for Call 2

async function searchDomain(domain) {
  try {
    console.log(`Searching for recent scans of: ${domain}\n`);

    const response = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=5`,
      {
        headers: {
          "API-Key": URLSCAN_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Search failed with status ${response.status}`);
    }

    const data = await response.json();

    console.log(`Found ${data.total} total scans`);
    console.log(`Processing first ${data.results.length} results\n`);

    return data.results;

  } catch (error) {
    console.log("Search failed:", error.message);
    return [];
  }
}

// ============================================
// CALL 2 — FETCH FULL VERDICT
// ============================================
// Takes a scan ID from Call 1 and fetches the
// complete result including verdict, score,
// tags, and screenshot URL

async function fetchVerdict(scanId) {
  try {
    const response = await fetch(
      `https://urlscan.io/api/v1/result/${scanId}/`,
      {
        headers: {
          "API-Key": URLSCAN_API_KEY,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Verdict fetch failed with status ${response.status}`);
    }

    const data = await response.json();

    // Extract just the fields we care about
    return {
      scanId: scanId,
      url: data.page?.url ?? "unknown",
      domain: data.page?.domain ?? "unknown",
      malicious: data.verdicts?.overall?.malicious ?? false,
      score: data.verdicts?.overall?.score ?? 0,
      tags: data.verdicts?.overall?.tags ?? [],
      categories: data.verdicts?.overall?.categories ?? [],
      screenshot: data.task?.screenshotURL ?? null,
      scannedAt: data.task?.time ?? null,
    };

  } catch (error) {
    console.log(`Verdict fetch failed for ${scanId}:`, error.message);
    return null;
  }
}

// ============================================
// COMBINED — SEARCH AND FETCH ALL VERDICTS
// ============================================
// Runs both calls together and returns
// a complete picture of each scanned URL

async function getFullScanData(domain) {
  try {
    // Call 1 — get list of scans
    const scans = await searchDomain(domain);

    if (scans.length === 0) {
      console.log("No scans found for this domain");
      return [];
    }

    console.log("Fetching full verdict data for each scan...\n");

    // Call 2 — fetch verdict for each scan
    // Adding 500ms delay between calls to respect rate limits
    const fullResults = [];

    for (const scan of scans) {
      const verdict = await fetchVerdict(scan._id);

      if (verdict) {
        fullResults.push(verdict);
      }

      // Small delay between calls
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    return fullResults;

  } catch (error) {
    console.log("Full scan data fetch failed:", error.message);
    return [];
  }
}

// ============================================
// RUN IT AND DISPLAY RESULTS
// ============================================

async function run() {
  const results = await getFullScanData("vercel.app");

  if (results.length === 0) {
    console.log("No results to display");
    return;
  }

  console.log("============================================");
  console.log("     URLSCAN.IO VERDICT REPORT");
  console.log("============================================\n");

  results.forEach((result, index) => {
    const status = result.malicious ? "🔴 MALICIOUS" : "🟢 CLEAN";

    console.log(`--- Result ${index + 1} ---`);
    console.log(`Status:     ${status}`);
    console.log(`URL:        ${result.url}`);
    console.log(`Score:      ${result.score}`);
    console.log(`Tags:       ${result.tags.length > 0 ? result.tags.join(", ") : "none"}`);
    console.log(`Categories: ${result.categories.length > 0 ? result.categories.join(", ") : "none"}`);
    console.log(`Screenshot: ${result.screenshot ?? "not available"}`);
    console.log(`Scanned:    ${result.scannedAt}`);
    console.log("");
  });

  // Summary
  const maliciousCount = results.filter((r) => r.malicious).length;
  const cleanCount = results.filter((r) => !r.malicious).length;

  console.log("============================================");
  console.log("SUMMARY");
  console.log(`Total Scanned:  ${results.length}`);
  console.log(`🔴 Malicious:   ${maliciousCount}`);
  console.log(`🟢 Clean:       ${cleanCount}`);
  console.log("============================================");
}

run();