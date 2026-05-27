//=============================================
// config.js
// Central configuration for Week 4
// Phishing Detector
//=============================================

// ============================================
// KNOWN BRANDS
// ============================================
// Brand names to detect in page content
// Maps brand name to its legitimate domain
// If brand appears on a different domain = suspicious

export const KNOWN_BRANDS = {
  paypal:    "paypal.com",
  interac:   "interac.ca",
  instagram: "instagram.com",
  facebook:  "facebook.com",
  apple:     "apple.com",
  google:    "google.com",
  microsoft: "microsoft.com",
  amazon:    "amazon.com",
  netflix:   "netflix.com",
  scotiabank:"scotiabank.com",
  tdbank:    "td.com",
  rbc:       "rbc.com",
  cibc:      "cibc.com",
  chase:     "chase.com",
  wellsfargo:"wellsfargo.com",
  vercel:    "vercel.com",
};

// ============================================
// ANALYZER WEIGHTS
// ============================================
// How much each content analyzer contributes
// to the final combined score

export const ANALYZER_WEIGHTS = {
  forms:       0.35,
  brands:      0.30,
  credentials: 0.20,
  title:       0.15,
};

// ============================================
// VERDICT THRESHOLDS
// ============================================

export const VERDICT_THRESHOLDS = {
  HIGH:   70,
  MEDIUM: 40,
  LOW:    10,
};

// ============================================
// ACTIONS
// ============================================

export const ACTIONS = {
  HIGH:   "AUTO TAKEDOWN",
  MEDIUM: "ESCALATE TO HUMAN REVIEW",
  LOW:    "MONITOR",
  CLEAN:  "CLEAR",
  ERROR:  "INVALID INPUT",
};

// ============================================
// FETCH CONFIG
// ============================================

export const FETCH_CONFIG = {
  timeoutMs:  8000,
  maxBodySize: 500000,  // 500KB max page size
  userAgent:  "Mozilla/5.0 (compatible; TrustSafetyBot/1.0)",
};

// ============================================
// CREDENTIAL KEYWORDS
// ============================================
// Words in form fields that indicate
// credential harvesting

export const CREDENTIAL_KEYWORDS = [
  "password",
  "passwd",
  "pwd",
  "pin",
  "ssn",
  "social security",
  "credit card",
  "card number",
  "cvv",
  "expiry",
  "sin",
  "date of birth",
  "dob",
];
