//=============================================
// validators.js
// All input validation for the system
// Every module that accepts input imports
// from here instead of writing its own checks
//=============================================

// ============================================
// URL VALIDATOR
// ============================================

export function validateURL(url) {
  if (!url || typeof url !== "string") {
    return {
      valid: false,
      error: "URL must be a non-empty string",
    };
  }

  if (url.trim() === "") {
    return {
      valid: false,
      error: "URL cannot be empty or whitespace",
    };
  }

  try {
    const parsed = new URL(url);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return {
        valid: false,
        error: "URL must use http or https protocol",
      };
    }

    return {
      valid: true,
      parsed,
      hostname: parsed.hostname,
      protocol: parsed.protocol,
    };

  } catch {
    return {
      valid: false,
      error: `Invalid URL format: ${url}`,
    };
  }
}

// ============================================
// BATCH VALIDATOR
// ============================================
// Validates a list of URLs before batch scanning
// Returns valid URLs and a report of invalid ones

export function validateBatch(urls) {
  if (!Array.isArray(urls)) {
    return {
      valid: false,
      error: "Input must be an array of URLs",
      validURLs: [],
      invalidURLs: [],
    };
  }

  if (urls.length === 0) {
    return {
      valid: false,
      error: "URL array cannot be empty",
      validURLs: [],
      invalidURLs: [],
    };
  }

  const validURLs = [];
  const invalidURLs = [];

  urls.forEach((url) => {
    const result = validateURL(url);
    if (result.valid) {
      validURLs.push(url);
    } else {
      invalidURLs.push({ url, reason: result.error });
    }
  });

  return {
    valid: validURLs.length > 0,
    validURLs,
    invalidURLs,
    totalValid: validURLs.length,
    totalInvalid: invalidURLs.length,
  };
}

// ============================================
// API KEY VALIDATOR
// ============================================
// Confirms required API keys exist before
// any API calls are attempted

export function validateAPIKeys() {
  const required = {
    URLSCAN_API_KEY: process.env.URLSCAN_API_KEY,
    GOOGLE_SAFE_BROWSING_KEY: process.env.GOOGLE_SAFE_BROWSING_KEY,
  };

  const missing = [];

  for (const [name, value] of Object.entries(required)) {
    if (!value || value.trim() === "") {
      missing.push(name);
    }
  }

  if (missing.length > 0) {
    return {
      valid: false,
      error: `Missing API keys: ${missing.join(", ")}`,
      missing,
    };
  }

  return {
    valid: true,
    keys: {
      urlscan: required.URLSCAN_API_KEY,
      google: required.GOOGLE_SAFE_BROWSING_KEY,
    },
  };
}