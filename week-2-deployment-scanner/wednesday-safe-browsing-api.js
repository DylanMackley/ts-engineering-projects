//=============================================
// Week 2 - Wednesday
// Objective: Connect Google Safe Browsing API
// as a second independent signal source
// T&S Use Case: Cross-referencing URLs against
// Google's confirmed threat database of billions
// of known malicious sites
//=============================================

require("dotenv").config();

const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

if (!GOOGLE_KEY) {
  console.log("❌ GOOGLE_SAFE_BROWSING_KEY not found");
  process.exit(1);
}

console.log("✅ Google Safe Browsing key loaded\n");

// ============================================
// GOOGLE SAFE BROWSING CHECK
// ============================================
// Sends a list of URLs to Google's threat
// database and returns which ones are confirmed
// known threats and what type of threat they are

async function checkSafeBrowsing(urls) {
  try {
    console.log(`Checking ${urls.length} URLs against Google Safe Browsing...\n`);

    const requestBody = {
      client: {
        clientId: "ts-engineering-projects",
        clientVersion: "1.0.0",
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: urls.map((url) => ({ url })),
      },
    };

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestBody),
      }
    );

    if (!response.ok) {
      throw new Error(`Safe Browsing API failed with status ${response.status}`);
    }

    const data = await response.json();

    // If no matches Google returns an empty object
    // meaning all URLs are clean in their database
    if (!data.matches || data.matches.length === 0) {
      console.log("✅ No threats found in Google Safe Browsing database\n");
      return [];
    }

    console.log(`⚠️  Found ${data.matches.length} threat matches\n`);
    return data.matches;

  } catch (error) {
    console.log("Safe Browsing check failed:", error.message);
    return [];
  }
}

// ============================================
// FORMAT AND DISPLAY RESULTS
// ============================================

function displayResults(urls, matches) {
  console.log("============================================");
  console.log("   GOOGLE SAFE BROWSING REPORT");
  console.log("============================================\n");

  // Create a lookup of which URLs had matches
  const matchedURLs = new Set(
    matches.map((m) => m.threat.url)
  );

  urls.forEach((url) => {
    const isMatch = matchedURLs.has(url);
    const match = matches.find((m) => m.threat.url === url);

    console.log(`URL: ${url}`);

    if (isMatch && match) {
      console.log(`Status:   🔴 THREAT CONFIRMED`);
      console.log(`Type:     ${match.threatType}`);
      console.log(`Platform: ${match.platformType}`);
    } else {
      console.log(`Status:   🟢 NOT IN GOOGLE DATABASE`);
    }

    console.log("");
  });

  // Summary
  console.log("============================================");
  console.log("SUMMARY");
  console.log(`Total Checked:    ${urls.length}`);
  console.log(`🔴 Threats Found: ${matches.length}`);
  console.log(`🟢 Clean:         ${urls.length - matches.length}`);
  console.log("============================================");
}

// ============================================
// RUN IT
// ============================================
// Testing with URLs from Tuesday's results
// including the confirmed phishing site

async function run() {
  const urlsToCheck = [
    "https://htyd.vercel.app/",
    "https://instagrmm.vercel.app/",
    "https://interac-online.vercel.app/",
    "https://mckeepa.vercel.app/",
    "https://my-portfolio.vercel.app/",
    "https://secure-login-verify.vercel.app/",
    "https://paypal-password-reset-account.vercel.app/",
  ];

  const matches = await checkSafeBrowsing(urlsToCheck);
  displayResults(urlsToCheck, matches);
}

run();