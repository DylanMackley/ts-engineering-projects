//=============================================
// config.js
// Central configuration for the entire system
// Every other module imports from here
// Change detection behavior by editing this
// file only — nothing else needs to change
//=============================================

// ============================================
// KEYWORD WEIGHTS
// ============================================
// How many points each keyword adds to the
// combined risk score when found in a URL

export const KEYWORD_WEIGHTS = {
  login: 10,
  verify: 10,
  secure: 8,
  account: 8,
  update: 7,
  confirm: 9,
  password: 15,
  signin: 10,
  banking: 12,
  authentication: 8,
};

// ============================================
// SIGNAL WEIGHTS
// ============================================
// How much each signal source contributes
// to the final combined score

export const SIGNAL_WEIGHTS = {
  googleThreat: 50,
  urlscanMalicious: 45,
  urlscanScore: 0.3,
  keywordScore: 1,
};

// ============================================
// VERDICT THRESHOLDS
// ============================================
// Combined score ranges that determine
// the final verdict tier

export const VERDICT_THRESHOLDS = {
  HIGH: 70,
  MEDIUM: 40,
  LOW: 10,
};

// ============================================
// ACTIONS
// ============================================
// What happens at each verdict tier

export const ACTIONS = {
  HIGH: "AUTO TAKEDOWN",
  MEDIUM: "ESCALATE TO HUMAN REVIEW",
  LOW: "MONITOR",
  CLEAN: "CLEAR",
  ERROR: "INVALID INPUT",
};

// ============================================
// RATE LIMITS
// ============================================
// Delays between API calls to stay within
// free tier limits on external services

export const RATE_LIMITS = {
  delayBetweenURLs: 1500,
  delayBetweenAPICalls: 500,
};

// ============================================
// API ENDPOINTS
// ============================================

export const API_ENDPOINTS = {
  urlscanSearch: "https://urlscan.io/api/v1/search",
  urlscanResult: "https://urlscan.io/api/v1/result",
  googleSafeBrowsing:
    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
};