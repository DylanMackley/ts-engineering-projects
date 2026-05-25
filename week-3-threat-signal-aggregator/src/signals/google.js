//=============================================
// signals/google.js
// Google Safe Browsing signal collector
// Third signal layer — checks against Google's
// confirmed threat database of billions of
// known malicious URLs updated in real time
//=============================================

import { API_ENDPOINTS } from "../config.js";

const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

// ============================================
// THREAT TYPES TO CHECK
// ============================================

const THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

// ============================================
// MAIN — COLLECT GOOGLE SIGNAL
// ============================================

export async function collectGoogleSignal(url) {
  try {
    const requestBody = {
      client: {
        clientId: "ts-engineering-projects",
        clientVersion: "1.0.0",
      },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    };

    const response = await fetch(
      `${API_ENDPOINTS.googleSafeBrowsing}?key=${GOOGLE_KEY}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestBody),
      }
    );

    if (!response.ok) {
      throw new Error(
        `Google Safe Browsing failed — status ${response.status}`
      );
    }

    const data = await response.json();
    const match = data.matches?.[0];

    if (!match) {
      return {
        signal: "google",
        fired: false,
        threat: false,
        threatType: null,
        platformType: null,
        summary: "not in Google threat database",
      };
    }

    return {
      signal: "google",
      fired: true,
      threat: true,
      threatType: match.threatType,
      platformType: match.platformType,
      summary: `confirmed threat — ${match.threatType}`,
    };

  } catch (error) {
    return {
      signal: "google",
      fired: false,
      threat: false,
      threatType: null,
      error: error.message,
      summary: "signal collection failed",
    };
  }
}

// ============================================
// BATCH — CHECK MULTIPLE URLS AT ONCE
// ============================================
// Google Safe Browsing supports checking
// multiple URLs in a single API call
// More efficient than one call per URL

export async function collectGoogleBatchSignal(urls) {
  try {
    const requestBody = {
      client: {
        clientId: "ts-engineering-projects",
        clientVersion: "1.0.0",
      },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: urls.map((url) => ({ url })),
      },
    };

    const response = await fetch(
      `${API_ENDPOINTS.googleSafeBrowsing}?key=${GOOGLE_KEY}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestBody),
      }
    );

    if (!response.ok) {
      throw new Error(
        `Google batch check failed — status ${response.status}`
      );
    }

    const data = await response.json();
    const matches = data.matches ?? [];

    // Build a result for every URL
    return urls.map((url) => {
      const match = matches.find((m) => m.threat.url === url);

      return {
        url,
        signal: "google",
        fired: !!match,
        threat: !!match,
        threatType: match?.threatType ?? null,
        summary: match
          ? `confirmed threat — ${match.threatType}`
          : "not in Google threat database",
      };
    });

  } catch (error) {
    return urls.map((url) => ({
      url,
      signal: "google",
      fired: false,
      threat: false,
      error: error.message,
    }));
  }
}