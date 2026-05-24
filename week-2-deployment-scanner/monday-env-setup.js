//=============================================
// Week 2 - Monday
// Objective: Load environment variables and
// make your first real API call to URLScan.io
// T&S Use Case: Connecting your detection
// system to real threat intelligence data
//=============================================

// Load dotenv - this reads your .env file and
// makes your API keys available in your code
require("dotenv").config();

// --- CONFIRM YOUR KEYS LOADED ---
// Never log actual key values in real projects
// This just confirms they exist without exposing them

const urlscanKey = process.env.URLSCAN_API_KEY;
const googleKey = process.env.GOOGLE_SAFE_BROWSING_KEY;

if (!urlscanKey) {
  console.log("❌ URLSCAN_API_KEY not found — check your .env file");
  process.exit(1);
}

if (!googleKey) {
  console.log("❌ GOOGLE_SAFE_BROWSING_KEY not found — check your .env file");
  process.exit(1);
}

console.log("✅ URLScan API key loaded");
console.log("✅ Google Safe Browsing key loaded");
console.log("✅ Environment configured correctly\n");

// --- YOUR FIRST REAL API CALL ---
// This searches URLScan.io for recent scans
// of vercel.app deployments
// These are real scans of real URLs on the internet

async function fetchRecentVercelScans() {
  try {
    console.log("Fetching recent vercel.app scans from URLScan.io...\n");

    const response = await fetch(
      "https://urlscan.io/api/v1/search/?q=domain:vercel.app&size=5",
      {
        headers: {
          "API-Key": urlscanKey,
          "Content-Type": "application/json",
        },
      }
    );

    // Check if the API responded successfully
    if (!response.ok) {
      throw new Error(`API responded with status ${response.status}`);
    }

    // Parse the JSON response
    const data = await response.json();

    console.log(`Total scans found: ${data.total}`);
    console.log(`Showing first ${data.results.length} results:\n`);

    // Loop through each result and display key information
   data.results.forEach((scan, index) => {
  console.log(`--- Scan ${index + 1} ---`);
  console.log(`URL:      ${scan.page.url}`);
  console.log(`Domain:   ${scan.page.domain}`);
  console.log(`Scanned:  ${scan.task.time}`);
  console.log(`Scan ID:  ${scan._id}`);
  console.log(`Result:   https://urlscan.io/result/${scan._id}/`);
  console.log("");
});

  } catch (error) {
    console.log("API call failed:", error.message);
  }
}

// Run the function
fetchRecentVercelScans();