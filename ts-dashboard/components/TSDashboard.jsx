"use client";

import { useState, useEffect, useCallback } from "react";

// ============================================
// CONFIG
// ============================================

const VERDICT_CONFIG = {
  HIGH:   { pill: "bg-red-50 text-red-600 ring-1 ring-red-200",       dot: "bg-red-500",     scoreText: "text-red-500",    rowAccent: "border-l-red-400",    barColor: "bg-red-400"    },
  MEDIUM: { pill: "bg-amber-50 text-amber-600 ring-1 ring-amber-200",  dot: "bg-amber-400",   scoreText: "text-amber-500",  rowAccent: "border-l-amber-400",  barColor: "bg-amber-400"  },
  LOW:    { pill: "bg-orange-50 text-orange-600 ring-1 ring-orange-200",dot: "bg-orange-400",  scoreText: "text-orange-500", rowAccent: "border-l-orange-300", barColor: "bg-orange-300" },
  CLEAN:  { pill: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200", dot: "bg-emerald-500", scoreText: "text-emerald-600", rowAccent: "border-l-emerald-400", barColor: "bg-emerald-400" },
  ERROR:  { pill: "bg-gray-100 text-gray-500 ring-1 ring-gray-200",    dot: "bg-gray-300",    scoreText: "text-gray-400",   rowAccent: "border-l-gray-200",   barColor: "bg-gray-200"   },
  SCANNING:{ pill: "bg-blue-50 text-blue-600 ring-1 ring-blue-200",   dot: "bg-blue-400",    scoreText: "text-blue-500",   rowAccent: "border-l-blue-300",   barColor: "bg-blue-300"   },
};

const SIGNAL_ICONS = {
  keywords:  "⬡",
  urlscan:   "◈",
  google:    "◎",
  velocity:  "⬟",
  content:   "◇",
};

// ============================================
// COMPONENTS
// ============================================

function ScoreArc({ score, verdict }) {
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.CLEAN;
  const r = 30, circ = 2 * Math.PI * r;
  const fill = (score / 100) * circ;
  return (
    <div className="relative w-20 h-20 flex items-center justify-center flex-shrink-0">
      <svg className="absolute inset-0 -rotate-90" width="80" height="80">
        <circle cx="40" cy="40" r={r} fill="none" stroke="#f1f5f9" strokeWidth="5" />
        <circle cx="40" cy="40" r={r} fill="none" stroke="currentColor"
          className={cfg.scoreText} strokeWidth="5"
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.7s cubic-bezier(.4,0,.2,1)" }} />
      </svg>
      <div className="text-center z-10">
        <div className={`text-xl font-semibold ${cfg.scoreText}`}>{score}</div>
        <div className="text-gray-400 text-xs">/ 100</div>
      </div>
    </div>
  );
}

function SignalBar({ name, signal }) {
  if (!signal) return null;
  const score = signal.score ?? 0;
  const verdictColors = {
    high:   { text: "text-red-500",     bar: "bg-red-400"     },
    medium: { text: "text-amber-500",   bar: "bg-amber-400"   },
    low:    { text: "text-orange-400",  bar: "bg-orange-300"  },
    clean:  { text: "text-emerald-600", bar: "bg-emerald-400" },
    error:  { text: "text-gray-400",    bar: "bg-gray-200"    },
  };
  const v = score >= 70 ? "high" : score >= 40 ? "medium" : score >= 10 ? "low" : signal.error ? "error" : "clean";
  const vc = verdictColors[v];
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-gray-300 text-sm">{SIGNAL_ICONS[name] || "·"}</span>
          <span className="text-gray-600 text-sm capitalize">{name}</span>
        </div>
        <span className={`text-sm font-semibold tabular-nums ${vc.text}`}>
          {signal.error ? "ERR" : score}
        </span>
      </div>
      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full ${vc.bar} rounded-full transition-all duration-700`}
          style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

function CaseRow({ c, isSelected, onClick }) {
  const cfg = VERDICT_CONFIG[c.verdict] || VERDICT_CONFIG.CLEAN;
  const domain = (c.url || "").replace("https://", "").replace(/\/$/, "");
  const isScanning = c.verdict === "SCANNING";
  return (
    <button onClick={onClick}
      className={`w-full text-left px-4 py-3.5 rounded-2xl border-l-4 border border-gray-100 transition-all duration-150 ${cfg.rowAccent} ${
        isSelected ? "bg-gray-50 shadow-sm" : "bg-white hover:bg-gray-50/60"}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-3 min-w-0">
          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot} ${isScanning ? "animate-pulse" : ""}`} />
          <div className="min-w-0">
            <div className="text-sm font-medium text-gray-800 truncate">{domain}</div>
            <div className="text-xs text-gray-400 mt-0.5">
              {isScanning ? "Scanning..." : `${c.firedSignals?.length ?? 0} signal(s) fired`}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {!isScanning && (
            <span className={`text-base font-semibold tabular-nums ${cfg.scoreText}`}>
              {c.combinedScore}
            </span>
          )}
          <span className={`text-xs font-medium px-2.5 py-0.5 rounded-full ${cfg.pill}`}>
            {c.verdict}
          </span>
        </div>
      </div>
    </button>
  );
}

function FeedItem({ item, onScan, isQueued }) {
  const domain = (item.url || "").replace("https://", "").replace(/\/$/, "");
  const submitted = item.submitted
    ? new Date(item.submitted).toISOString().slice(0, 16).replace("T", " ")
    : "";
  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-gray-50 hover:bg-gray-50/60 transition-colors">
      <div className="min-w-0 flex-1">
        <div className="text-sm text-gray-700 font-medium truncate">{domain}</div>
        <div className="text-xs text-gray-400 mt-0.5">{submitted}</div>
      </div>
      <button onClick={() => onScan(item.url)}
        disabled={isQueued}
        className={`ml-3 flex-shrink-0 text-xs px-3 py-1.5 rounded-full font-medium transition-all ${
          isQueued
            ? "bg-blue-50 text-blue-400 cursor-not-allowed"
            : "bg-gray-900 text-white hover:bg-gray-700"}`}>
        {isQueued ? "Queued" : "Scan"}
      </button>
    </div>
  );
}

// ============================================
// MAIN DASHBOARD
// ============================================

export default function TSDashboard() {
  const [activeTab, setActiveTab] = useState("scanner");
  const [cases, setCases] = useState([]);
  const [selected, setSelected] = useState(null);
  const [manualURL, setManualURL] = useState("");
  const [scanning, setScanning] = useState(false);
  const [feedItems, setFeedItems] = useState([]);
  const [feedLoading, setFeedLoading] = useState(false);
  const [feedError, setFeedError] = useState(null);
  const [lastFetch, setLastFetch] = useState(null);
  const [queuedURLs, setQueuedURLs] = useState(new Set());
  const [scanQueue, setScanQueue] = useState([]);

  // ── Summary ─────────────────────────────────────────────────────────────────
  const summary = {
    total:  cases.filter(c => c.verdict !== "SCANNING").length,
    high:   cases.filter(c => c.verdict === "HIGH").length,
    medium: cases.filter(c => c.verdict === "MEDIUM").length,
    low:    cases.filter(c => c.verdict === "LOW").length,
    clean:  cases.filter(c => c.verdict === "CLEAN").length,
  };

  // ── Scan a single URL ────────────────────────────────────────────────────────
  const scanURL = useCallback(async (url) => {
    if (!url || !url.startsWith("http")) return;

    // Add placeholder
    const placeholder = {
      caseId: `SCANNING-${Date.now()}`,
      url,
      verdict: "SCANNING",
      combinedScore: 0,
      firedSignals: [],
      signals: {},
      scannedAt: new Date().toISOString(),
    };

    setCases(prev => [placeholder, ...prev]);
    setSelected(placeholder.caseId);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const result = await res.json();

      setCases(prev =>
        prev.map(c => c.caseId === placeholder.caseId ? result : c)
      );
      setSelected(result.caseId);
    } catch {
      setCases(prev =>
        prev.map(c =>
          c.caseId === placeholder.caseId
            ? { ...placeholder, verdict: "ERROR", error: "Scan failed" }
            : c
        )
      );
    } finally {
      setQueuedURLs(prev => { const n = new Set(prev); n.delete(url); return n; });
    }
  }, []);

  // ── Process scan queue (one at a time) ──────────────────────────────────────
  useEffect(() => {
    if (scanQueue.length === 0 || scanning) return;
    const [next, ...rest] = scanQueue;
    setScanQueue(rest);
    setScanning(true);
    scanURL(next).finally(() => setScanning(false));
  }, [scanQueue, scanning, scanURL]);

  // ── Queue a URL from feed ────────────────────────────────────────────────────
  const queueScan = useCallback((url) => {
    if (queuedURLs.has(url)) return;
    setQueuedURLs(prev => new Set(prev).add(url));
    setScanQueue(prev => [...prev, url]);
    setActiveTab("scanner");
  }, [queuedURLs]);

  // ── Manual scan ─────────────────────────────────────────────────────────────
  const handleManualScan = () => {
    const url = manualURL.trim();
    if (!url) return;
    queueScan(url.startsWith("http") ? url : `https://${url}`);
    setManualURL("");
  };

  // ── Fetch live feed ──────────────────────────────────────────────────────────
  const fetchFeed = useCallback(async () => {
    setFeedLoading(true);
    setFeedError(null);
    try {
      const res = await fetch("/api/feed");
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setFeedItems(data.urls ?? []);
      setLastFetch(new Date().toISOString().slice(0, 16).replace("T", " "));
    } catch (err) {
      setFeedError(err instanceof Error ? err.message : "Feed failed");
    } finally {
      setFeedLoading(false);
    }
  }, []);

  // Auto-fetch feed on mount and every 60 seconds
  useEffect(() => {
    fetchFeed();
    const interval = setInterval(fetchFeed, 60000);
    return () => clearInterval(interval);
  }, [fetchFeed]);

  const selectedCase = cases.find(c => c.caseId === selected);

  return (
    <div className="min-h-screen bg-[#f9f9f9]"
      style={{ fontFamily: "-apple-system, 'SF Pro Text', BlinkMacSystemFont, 'Helvetica Neue', sans-serif" }}>

      {/* Nav */}
      <div className="bg-white/80 backdrop-blur-xl border-b border-gray-200/60 sticky top-0 z-20">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-gray-900 flex items-center justify-center">
              <span className="text-white text-xs font-semibold">TS</span>
            </div>
            <span className="text-sm font-semibold text-gray-900">Phishing Detector</span>
            <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">v4.0 — Live</span>
          </div>
          <div className="flex items-center gap-4 text-xs text-gray-400">
            {lastFetch && <span>Feed updated {lastFetch}</span>}
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block animate-pulse" />
              <span className="text-emerald-600 font-medium">Live</span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-6 py-10">

        {/* Title */}
        <div className="mb-8">
          <h1 className="text-3xl font-semibold text-gray-900 tracking-tight">
            Vercel Deployment Monitor
          </h1>
          <p className="text-gray-500 mt-1 text-sm">
            Real-time phishing detection across vercel.app deployments
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-3 mb-8">
          {[
            { label: "Scanned",  value: summary.total,  color: "text-gray-800"    },
            { label: "High",     value: summary.high,   color: "text-red-500"     },
            { label: "Medium",   value: summary.medium, color: "text-amber-500"   },
            { label: "Low",      value: summary.low,    color: "text-orange-500"  },
            { label: "Clean",    value: summary.clean,  color: "text-emerald-600" },
          ].map(s => (
            <div key={s.label} className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
              <div className={`text-4xl font-semibold tracking-tight ${s.color}`}>{s.value}</div>
              <div className="text-gray-400 text-xs mt-2">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-gray-100 rounded-xl p-1 w-fit">
          {[
            { id: "scanner", label: "Scanner"   },
            { id: "feed",    label: "Live Feed"  },
          ].map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? "bg-white text-gray-900 shadow-sm"
                  : "text-gray-500 hover:text-gray-800"}`}>
              {tab.label}
              {tab.id === "feed" && feedItems.length > 0 && (
                <span className="ml-2 text-xs bg-blue-100 text-blue-600 px-1.5 py-0.5 rounded-full">
                  {feedItems.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Scanner Tab */}
        {activeTab === "scanner" && (
          <div className="space-y-5">
            {/* URL Input */}
            <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-5">
              <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">
                Scan a URL
              </div>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={manualURL}
                  onChange={e => setManualURL(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleManualScan()}
                  placeholder="https://suspicious-site.vercel.app"
                  className="flex-1 text-sm border border-gray-200 rounded-xl px-4 py-2.5 outline-none focus:border-gray-400 transition-colors font-mono"
                />
                <button onClick={handleManualScan}
                  disabled={!manualURL.trim() || scanning}
                  className="px-5 py-2.5 bg-gray-900 text-white text-sm font-medium rounded-xl hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                  {scanning ? "Scanning..." : "Scan"}
                </button>
              </div>
              {scanQueue.length > 0 && (
                <div className="mt-3 text-xs text-gray-400">
                  {scanQueue.length} URL{scanQueue.length !== 1 ? "s" : ""} queued
                </div>
              )}
            </div>

            {/* Cases */}
            {cases.length === 0 ? (
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-12 text-center">
                <div className="text-gray-400 text-sm">No scans yet</div>
                <div className="text-gray-300 text-xs mt-1">
                  Paste a URL above or scan from the Live Feed
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-5 gap-5">
                {/* Case list */}
                <div className="col-span-2 space-y-2">
                  <p className="text-xs text-gray-400 uppercase tracking-wider px-1 mb-3">
                    {cases.length} case{cases.length !== 1 ? "s" : ""} · most recent first
                  </p>
                  {cases.map((c) => (
                    <CaseRow
                      key={c.caseId}
                      c={c}
                      isSelected={c.caseId === selected}
                      onClick={() => setSelected(c.caseId)}
                    />
                  ))}
                </div>

                {/* Case detail */}
                {selectedCase && selectedCase.verdict !== "SCANNING" && (
                  <div className="col-span-3 space-y-4">
                    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
                      <div className="flex items-start justify-between gap-4 mb-6">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-2.5">
                            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${(VERDICT_CONFIG[selectedCase.verdict] || VERDICT_CONFIG.CLEAN).pill}`}>
                              {selectedCase.verdict}
                            </span>
                            <span className="text-xs text-gray-400">{selectedCase.action}</span>
                          </div>
                          <p className="text-gray-800 font-medium text-sm break-all">
                            {selectedCase.url}
                          </p>
                          <p className="text-gray-400 text-xs font-mono mt-1.5">
                            {selectedCase.caseId}
                          </p>
                        </div>
                        <ScoreArc
                          score={selectedCase.combinedScore}
                          verdict={selectedCase.verdict}
                        />
                      </div>

                      {/* Signal bars */}
                      <div className="grid grid-cols-2 gap-x-8 gap-y-3">
                        {Object.entries(selectedCase.signals || {}).map(([name, signal]) => (
                          <SignalBar key={name} name={name} signal={signal} />
                        ))}
                      </div>

                      {/* Fired signals */}
                      {selectedCase.firedSignals?.length > 0 && (
                        <div className="mt-5 pt-4 border-t border-gray-50 flex flex-wrap gap-1.5">
                          {selectedCase.firedSignals.map(s => (
                            <span key={s}
                              className="text-xs text-gray-500 bg-gray-50 border border-gray-200 px-2.5 py-0.5 rounded-full font-mono">
                              {s}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Content findings */}
                    {selectedCase.signals?.content?.findings?.length > 0 && (
                      <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-5">
                        <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">
                          Content Findings
                        </div>
                        <div className="space-y-2">
                          {selectedCase.signals.content.findings.map((f, i) => (
                            <div key={i} className="flex gap-2 text-xs text-gray-600">
                              <span className="text-gray-300 flex-shrink-0">›</span>
                              <span className={f.startsWith("CRITICAL") ? "text-red-600 font-medium" : ""}>
                                {f}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Google threat */}
                    {selectedCase.signals?.google?.threat && (
                      <div className="bg-red-50 rounded-2xl border border-red-100 p-5">
                        <div className="text-xs font-semibold text-red-600 uppercase tracking-wider mb-1">
                          Google Safe Browsing — Confirmed Threat
                        </div>
                        <div className="text-sm text-red-700">
                          {selectedCase.signals.google.threatType}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Scanning state */}
                {selectedCase && selectedCase.verdict === "SCANNING" && (
                  <div className="col-span-3 bg-white rounded-2xl border border-gray-100 shadow-sm p-12 flex items-center justify-center">
                    <div className="text-center">
                      <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
                      <div className="text-gray-600 text-sm font-medium">Scanning</div>
                      <div className="text-gray-400 text-xs mt-1 font-mono break-all max-w-xs">
                        {selectedCase.url}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Live Feed Tab */}
        {activeTab === "feed" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium text-gray-700">
                  Recent Vercel Deployments on URLScan
                </div>
                <div className="text-xs text-gray-400 mt-0.5">
                  Auto-refreshes every 60 seconds · Click Scan to run detection
                </div>
              </div>
              <button onClick={fetchFeed} disabled={feedLoading}
                className="text-xs px-4 py-2 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-40 transition-colors">
                {feedLoading ? "Refreshing..." : "Refresh"}
              </button>
            </div>

            {feedError && (
              <div className="bg-red-50 border border-red-100 rounded-2xl p-4 text-sm text-red-600">
                {feedError}
              </div>
            )}

            {feedLoading && feedItems.length === 0 && (
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-12 text-center">
                <div className="w-6 h-6 border-2 border-gray-300 border-t-gray-600 rounded-full animate-spin mx-auto mb-3" />
                <div className="text-gray-400 text-sm">Fetching live feed...</div>
              </div>
            )}

            {!feedLoading && feedItems.length === 0 && !feedError && (
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-12 text-center">
                <div className="text-gray-400 text-sm">No results from URLScan</div>
                <div className="text-gray-300 text-xs mt-1">
                  Try refreshing or check your API key
                </div>
              </div>
            )}

            {feedItems.length > 0 && (
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-50 bg-gray-50/50">
                  <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    {feedItems.length} deployment{feedItems.length !== 1 ? "s" : ""} found
                  </div>
                </div>
                <div className="divide-y divide-gray-50 max-h-[600px] overflow-y-auto">
                  {feedItems.map((item, i) => (
                    <FeedItem
                      key={i}
                      item={item}
                      onScan={queueScan}
                      isQueued={queuedURLs.has(item.url)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
