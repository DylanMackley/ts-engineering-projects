import { NextRequest, NextResponse } from "next/server";
import { parse } from "node-html-parser";

// ============================================
// CONFIG
// ============================================

const KNOWN_BRANDS: Record<string, string> = {
  paypal: "paypal.com", interac: "interac.ca",
  instagram: "instagram.com", facebook: "facebook.com",
  apple: "apple.com", google: "google.com",
  microsoft: "microsoft.com", amazon: "amazon.com",
  netflix: "netflix.com", scotiabank: "scotiabank.com",
  vercel: "vercel.com",
};

const KEYWORD_WEIGHTS: Record<string, number> = {
  login: 10, verify: 10, secure: 8, account: 8,
  update: 7, confirm: 9, password: 15, signin: 10,
  banking: 12, authentication: 8,
};

const CREDENTIAL_KEYWORDS = [
  "password", "passwd", "pwd", "pin", "ssn",
  "social security", "credit card", "card number",
  "cvv", "expiry", "sin", "date of birth",
];

// ============================================
// HELPERS
// ============================================

function extractDomain(url: string): string {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    const parts = hostname.split(".");
    return parts.slice(-2).join(".");
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0];
  }
}

function extractHostname(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url;
  }
}

function generateCaseId(): string {
  return `CASE-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

// ============================================
// SIGNAL 1 — KEYWORDS
// ============================================

function checkKeywords(url: string) {
  let score = 0;
  const fired: string[] = [];
  const lower = url.toLowerCase();

  for (const [word, weight] of Object.entries(KEYWORD_WEIGHTS)) {
    if (lower.includes(word)) {
      score += weight;
      fired.push(`${word}(+${weight})`);
    }
  }

  return { signal: "keywords", score: Math.min(score, 100), fired, error: false };
}

// ============================================
// SIGNAL 2 — URLSCAN
// ============================================

async function checkURLScan(hostname: string) {
  try {
    const apiKey = process.env.URLSCAN_API_KEY;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (apiKey) headers["API-Key"] = apiKey;

    const res = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${hostname}&size=1`,
      { headers, signal: AbortSignal.timeout(5000) }
    );

    if (!res.ok) return { signal: "urlscan", score: 0, malicious: false, error: true };

    const data = await res.json();
    const result = data.results?.[0];
    const malicious = result?.verdicts?.overall?.malicious ?? false;
    const score = result?.verdicts?.overall?.score ?? 0;

    return { signal: "urlscan", score: Math.min(score, 100), malicious, error: false };
  } catch {
    return { signal: "urlscan", score: 0, malicious: false, error: true };
  }
}

// ============================================
// SIGNAL 3 — GOOGLE SAFE BROWSING
// ============================================

async function checkGoogle(url: string) {
  try {
    const apiKey = process.env.GOOGLE_API_KEY;
    if (!apiKey) return { signal: "google", score: 0, threat: false, threatType: null, error: false };

    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "ts-dashboard", clientVersion: "4.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!res.ok) return { signal: "google", score: 0, threat: false, threatType: null, error: true };

    const data = await res.json();
    const threat = data.matches?.length > 0;
    const threatType = data.matches?.[0]?.threatType ?? null;

    return { signal: "google", score: threat ? 100 : 0, threat, threatType, error: false };
  } catch {
    return { signal: "google", score: 0, threat: false, threatType: null, error: true };
  }
}

// ============================================
// SIGNAL 4 — VELOCITY
// ============================================

async function checkVelocity(url: string) {
  try {
    const domain = extractDomain(url);
    const res = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100`,
      { signal: AbortSignal.timeout(5000) }
    );

    if (!res.ok) return { signal: "velocity", score: 0, counts: { "7d": 0 }, error: true };

    const data = await res.json();
    const results = data.results ?? [];
    const now = Date.now();

    const counts = { "24h": 0, "7d": 0, "30d": 0 };
    for (const r of results) {
      const age = (now - new Date(r?.task?.time).getTime()) / 86400000;
      if (age <= 1)  counts["24h"]++;
      if (age <= 7)  counts["7d"]++;
      if (age <= 30) counts["30d"]++;
    }

    const score =
      counts["7d"] >= 50 ? 95 :
      counts["7d"] >= 20 ? 75 :
      counts["7d"] >= 8  ? 45 :
      counts["7d"] >= 3  ? 20 : 0;

    return { signal: "velocity", score, counts, error: false };
  } catch {
    return { signal: "velocity", score: 0, counts: { "7d": 0 }, error: true };
  }
}

// ============================================
// SIGNAL 5 — CONTENT ANALYSIS
// ============================================

async function checkContent(url: string) {
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; TrustSafetyBot/1.0)" },
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) return { signal: "content", score: 0, findings: [], error: true };

    const html = await res.text();
    const root = parse(html);
    const hostname = extractHostname(url);
    let score = 0;
    const findings: string[] = [];

    // Brand impersonation
    const text = root.querySelectorAll("title,h1,h2,p,button,label")
      .map(el => el.text.toLowerCase()).join(" ");

    for (const [brand, domain] of Object.entries(KNOWN_BRANDS)) {
      if (text.includes(brand) && !hostname.includes(domain.split(".")[0])) {
        score += 40;
        findings.push(`Brand "${brand}" detected on wrong domain`);
      }
    }

    // Credential fields
    const inputs = root.querySelectorAll("input");
    for (const input of inputs) {
      const attrs = [
        input.getAttribute("name") ?? "",
        input.getAttribute("id") ?? "",
        input.getAttribute("placeholder") ?? "",
        input.getAttribute("type") ?? "",
      ].join(" ").toLowerCase();

      for (const kw of CREDENTIAL_KEYWORDS) {
        if (attrs.includes(kw)) {
          score += 20;
          findings.push(`Credential field detected: "${kw}"`);
          break;
        }
      }
    }

    // External form targets
    for (const form of root.querySelectorAll("form")) {
      const action = form.getAttribute("action") ?? "";
      if (action.startsWith("http")) {
        const actionHost = extractHostname(action);
        if (actionHost !== hostname) {
          score += 50;
          findings.push(`Form submits to external domain: ${actionHost}`);
        }
      }
    }

    return {
      signal: "content",
      score: Math.min(score, 100),
      findings,
      error: false,
    };
  } catch {
    return { signal: "content", score: 0, findings: [], error: true };
  }
}

// ============================================
// FUSION
// ============================================

function fuse(url: string, signals: any[]) {
  let combined = 0;
  const fired: string[] = [];

  const weights: Record<string, number> = {
    keywords: 1,
    urlscan: 0.3,
    google: 1,
    velocity: 0.2,
    content: 0.4,
  };

  for (const s of signals) {
    if (s.error || s.score === 0) continue;

    if (s.signal === "google" && s.threat) {
      combined += 50;
      fired.push(`google_threat(+50)`);
      continue;
    }

    if (s.signal === "urlscan" && s.malicious) {
      combined += 45;
      fired.push(`urlscan_malicious(+45)`);
    }

    const w = weights[s.signal] ?? 0.2;
    const contribution = Math.round(s.score * w);
    if (contribution > 0) {
      combined += contribution;
      fired.push(`${s.signal}(+${contribution})`);
    }
  }

  combined = Math.min(combined, 100);

  const verdict =
    combined >= 70 ? "HIGH" :
    combined >= 40 ? "MEDIUM" :
    combined >= 10 ? "LOW" : "CLEAN";

  const action =
    verdict === "HIGH"   ? "AUTO TAKEDOWN" :
    verdict === "MEDIUM" ? "ESCALATE TO HUMAN REVIEW" :
    verdict === "LOW"    ? "MONITOR" : "CLEAR";

  return {
    caseId: generateCaseId(),
    url,
    combinedScore: combined,
    verdict,
    action,
    firedSignals: fired,
    signals: Object.fromEntries(signals.map(s => [s.signal, s])),
    scannedAt: new Date().toISOString(),
  };
}

// ============================================
// ROUTE HANDLER
// ============================================

export async function POST(req: NextRequest) {
  try {
    const { url } = await req.json();

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "URL required" }, { status: 400 });
    }

    if (!url.startsWith("http")) {
      return NextResponse.json({ error: "URL must start with http or https" }, { status: 400 });
    }

    const [urlscanResult, googleResult, velocityResult, contentResult] =
      await Promise.all([
        checkURLScan(extractHostname(url)),
        checkGoogle(url),
        checkVelocity(url),
        checkContent(url),
      ]);

    const keywordResult = checkKeywords(url);

    const result = fuse(url, [
      keywordResult,
      urlscanResult,
      googleResult,
      velocityResult,
      contentResult,
    ]);

    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: "Scan failed" }, { status: 500 });
  }
}
