//=============================================
// fetcher.js
// Fetches raw HTML from a target URL
// This is the data collection layer —
// everything else works on what this returns
//=============================================

import { FETCH_CONFIG } from "./config.js";

// ============================================
// MAIN — FETCH PAGE
// ============================================

export async function fetchPage(url) {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    FETCH_CONFIG.timeoutMs
  );

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": FETCH_CONFIG.userAgent,
        "Accept": "text/html",
      },
      redirect: "follow",
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return {
        success: false,
        url,
        error: `HTTP ${response.status} — ${response.statusText}`,
        html: null,
        finalURL: response.url,
      };
    }

    // Read body with size limit
    const reader = response.body.getReader();
    const chunks = [];
    let totalSize = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalSize += value.length;

      if (totalSize > FETCH_CONFIG.maxBodySize) {
        reader.cancel();
        break;
      }

      chunks.push(value);
    }

    const html = new TextDecoder().decode(
      Buffer.concat(chunks.map(c => Buffer.from(c)))
    );

    return {
      success:  true,
      url,
      finalURL: response.url,
      status:   response.status,
      html,
      size:     totalSize,
      redirected: response.redirected,
    };

  } catch (err) {
    clearTimeout(timeout);

    return {
      success: false,
      url,
      error:   err.name === "AbortError"
        ? `Request timed out after ${FETCH_CONFIG.timeoutMs}ms`
        : err.message,
      html:    null,
      finalURL: url,
    };
  }
}
