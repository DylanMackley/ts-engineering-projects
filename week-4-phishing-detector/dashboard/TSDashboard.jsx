import { useState } from "react";

const REPORT = {
  meta: { tool: "Phishing Detector", version: "4.0", generatedAt: "2026-05-27T20:51:09.663Z" },
  summary: { total: 4, high: 0, medium: 2, low: 1, clean: 1, errors: 0, flagRate: "50.0%" },
  cases: [
    {
      caseId: "CASE-1779915067921-290",
      url: "https://paypal-secure-login.vercel.app/",
      combinedScore: 68,
      verdict: "MEDIUM",
      action: "ESCALATE TO HUMAN REVIEW",
      firedSignals: ["forms(+31)", "brands(+15)", "credentials(+11)", "title(+11)"],
      signalCount: 4,
      analyzers: {
        forms: { score: 90, verdict: "high", findings: ["Form submits to external domain: evil-collector.com", "Form uses POST method — action: evil-collector.com/steal", "Form contains 4 hidden fields — possible data exfiltration"] },
        brands: { score: 50, verdict: "medium", findings: ['Brand "paypal" detected but domain is paypal-secure-login.vercel.app not paypal.com'], impersonated: ["paypal"] },
        credentials: { score: 55, verdict: "medium", findings: ["1 password input field detected", 'Credential keyword "password" found in input field'] },
        title: { score: 70, verdict: "high", findings: ['Title "PayPal - Log in to your account" references brand on wrong domain', 'Title contains suspicious word: "log in"'] },
      },
    },
    {
      caseId: "CASE-1779915068431-428",
      url: "https://interac-verify-account.vercel.app/",
      combinedScore: 55,
      verdict: "MEDIUM",
      action: "ESCALATE TO HUMAN REVIEW",
      firedSignals: ["forms(+9)", "brands(+15)", "credentials(+20)", "title(+11)"],
      signalCount: 4,
      analyzers: {
        forms: { score: 25, verdict: "low", findings: ["Form uses POST method", "Form has no action attribute — submits to current page"] },
        brands: { score: 50, verdict: "medium", findings: ['Brand "interac" detected but domain is interac-verify-account.vercel.app not interac.ca'], impersonated: ["interac"] },
        credentials: { score: 100, verdict: "high", findings: ["1 password input field detected", 'Keyword "sin" found in input', 'Keyword "card number" found', 'Keyword "cvv" found', "1 credit card input field detected", "CRITICAL: Password and credit card fields on same page"] },
        title: { score: 70, verdict: "high", findings: ['Title "Interac - Verify your account" references brand on wrong domain', 'Title contains suspicious word: "verify"'] },
      },
    },
    {
      caseId: "CASE-1779915069662-908",
      url: "https://my-portfolio.vercel.app/",
      combinedScore: 20,
      verdict: "LOW",
      action: "MONITOR",
      firedSignals: ["forms(+5)", "brands(+15)"],
      signalCount: 2,
      analyzers: {
        forms: { score: 15, verdict: "low", findings: ["Form has no action attribute — submits to current page"] },
        brands: { score: 50, verdict: "medium", findings: ['Brand "interac" mentioned — likely false positive on portfolio page'] },
        credentials: { score: 0, verdict: "clean", findings: ["No credential harvesting patterns detected"] },
        title: { score: 0, verdict: "clean", findings: ["Title \"Matthew Waddell's Portfolio\" — no suspicious patterns"] },
      },
    },
    {
      caseId: "CASE-1779915068947-958",
      url: "https://jane-smith-portfolio.vercel.app/",
      combinedScore: 9,
      verdict: "CLEAN",
      action: "CLEAR",
      firedSignals: ["forms(+9)"],
      signalCount: 1,
      analyzers: {
        forms: { score: 25, verdict: "low", findings: ["Contact form with POST method — no suspicious target"] },
        brands: { score: 0, verdict: "clean", findings: ["No brand impersonation detected"] },
        credentials: { score: 0, verdict: "clean", findings: ["No credential harvesting patterns detected"] },
        title: { score: 0, verdict: "clean", findings: ["Title \"Jane Smith — Frontend Developer\" — no suspicious patterns"] },
      },
    },
  ],
};

const VERDICT_CONFIG = {
  HIGH:   { pill: "bg-red-50 text-red-600 ring-1 ring-red-200",       dot: "bg-red-500",     scoreText: "text-red-500",    rowAccent: "border-l-red-400",    barColor: "bg-red-400"    },
  MEDIUM: { pill: "bg-amber-50 text-amber-600 ring-1 ring-amber-200",  dot: "bg-amber-400",   scoreText: "text-amber-500",  rowAccent: "border-l-amber-400",  barColor: "bg-amber-400"  },
  LOW:    { pill: "bg-orange-50 text-orange-600 ring-1 ring-orange-200",dot: "bg-orange-400",  scoreText: "text-orange-500", rowAccent: "border-l-orange-300", barColor: "bg-orange-300" },
  CLEAN:  { pill: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200", dot: "bg-emerald-500", scoreText: "text-emerald-600", rowAccent: "border-l-emerald-400", barColor: "bg-emerald-400" },
  ERROR:  { pill: "bg-gray-100 text-gray-500 ring-1 ring-gray-200",    dot: "bg-gray-400",    scoreText: "text-gray-400",   rowAccent: "border-l-gray-300",   barColor: "bg-gray-300"   },
};

const ANALYZER_VERDICT_COLOR = {
  high:   { text: "text-red-500",     bar: "bg-red-400"     },
  medium: { text: "text-amber-500",   bar: "bg-amber-400"   },
  low:    { text: "text-orange-400",  bar: "bg-orange-300"  },
  clean:  { text: "text-emerald-600", bar: "bg-emerald-400" },
};

const ANALYZER_META = {
  forms:       { label: "Forms",       icon: "⬡", desc: "Form targets & submission behavior" },
  brands:      { label: "Brands",      icon: "◈", desc: "Brand impersonation on wrong domain" },
  credentials: { label: "Credentials", icon: "⬟", desc: "Credential & payment field harvesting" },
  title:       { label: "Title",       icon: "◇", desc: "Page title impersonation patterns" },
};

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

function AnalyzerBar({ name, data }) {
  const vc = ANALYZER_VERDICT_COLOR[data.verdict] || ANALYZER_VERDICT_COLOR.clean;
  const meta = ANALYZER_META[name];
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-gray-300 text-sm">{meta.icon}</span>
          <span className="text-gray-600 text-sm">{meta.label}</span>
        </div>
        <span className={`text-sm font-semibold tabular-nums ${vc.text}`}>{data.score}</span>
      </div>
      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full ${vc.bar} rounded-full transition-all duration-700`} style={{ width: `${data.score}%` }} />
      </div>
    </div>
  );
}

function Findings({ analyzers }) {
  const active = Object.entries(analyzers).filter(([, d]) => d.score > 0);
  if (active.length === 0) return (
    <div className="rounded-2xl border border-emerald-100 bg-emerald-50 p-6 text-center">
      <div className="text-emerald-600 font-medium">No threats detected</div>
      <div className="text-emerald-400 text-sm mt-1">All analyzers returned clean results</div>
    </div>
  );
  return (
    <div className="space-y-3">
      {active.map(([name, data]) => {
        const vc = ANALYZER_VERDICT_COLOR[data.verdict] || ANALYZER_VERDICT_COLOR.clean;
        const meta = ANALYZER_META[name];
        return (
          <div key={name} className="rounded-2xl border border-gray-100 bg-gray-50/40 p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-gray-400">{meta.icon}</span>
                <span className="text-sm font-semibold text-gray-800">{meta.label}</span>
                <span className="text-xs text-gray-400 hidden sm:inline">{meta.desc}</span>
              </div>
              <span className={`text-sm font-bold ${vc.text}`}>{data.score}</span>
            </div>
            <div className="space-y-2">
              {data.findings.map((f, i) => (
                <div key={i} className={`flex gap-2 text-xs leading-relaxed ${f.startsWith("CRITICAL") ? "text-red-600 font-medium" : "text-gray-500"}`}>
                  <span className="text-gray-300 flex-shrink-0">›</span>
                  <span>{f}</span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function CaseRow({ c, isSelected, onClick }) {
  const cfg = VERDICT_CONFIG[c.verdict] || VERDICT_CONFIG.CLEAN;
  const domain = c.url.replace("https://", "").replace(/\/$/, "");
  return (
    <button onClick={onClick}
      className={`w-full text-left px-4 py-3.5 rounded-2xl border-l-4 border border-gray-100 transition-all duration-150 ${cfg.rowAccent} ${
        isSelected ? "bg-gray-50 shadow-sm" : "bg-white hover:bg-gray-50/60"}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-3 min-w-0">
          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
          <div className="min-w-0">
            <div className="text-sm font-medium text-gray-800 truncate">{domain}</div>
            <div className="text-xs text-gray-400 mt-0.5">{c.signalCount} signal{c.signalCount !== 1 ? "s" : ""} fired</div>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className={`text-base font-semibold tabular-nums ${cfg.scoreText}`}>{c.combinedScore}</span>
          <span className={`text-xs font-medium px-2.5 py-0.5 rounded-full ${cfg.pill}`}>{c.verdict}</span>
        </div>
      </div>
    </button>
  );
}

export default function TSDashboard() {
  const [selected, setSelected] = useState(0);
  const [activeTab, setActiveTab] = useState("cases");
  const c = REPORT.cases[selected];
  const cfg = VERDICT_CONFIG[c.verdict];
  const scanTime = new Date(REPORT.meta.generatedAt).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit",
  });

  return (
    <div className="min-h-screen bg-[#f9f9f9]" style={{ fontFamily: "-apple-system, 'SF Pro Text', BlinkMacSystemFont, 'Helvetica Neue', sans-serif" }}>

      {/* Nav */}
      <div className="bg-white/80 backdrop-blur-xl border-b border-gray-200/60 sticky top-0 z-20">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-gray-900 flex items-center justify-center">
              <span className="text-white text-xs font-semibold">TS</span>
            </div>
            <span className="text-sm font-semibold text-gray-900">Phishing Detector</span>
            <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">v{REPORT.meta.version}</span>
          </div>
          <div className="flex items-center gap-4 text-xs text-gray-400">
            <span>{scanTime}</span>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
              <span className="text-emerald-600 font-medium">Operational</span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-6 py-10">

        {/* Page Title */}
        <div className="mb-8">
          <h1 className="text-3xl font-semibold text-gray-900 tracking-tight">Triage Report</h1>
          <p className="text-gray-500 mt-1 text-sm">
            {REPORT.summary.total} deployments · {REPORT.summary.flagRate} flag rate · Forms, Brands, Credentials, Title
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-3 mb-8">
          {[
            { label: "Scanned",      value: REPORT.summary.total,  color: "text-gray-800"    },
            { label: "High Risk",    value: REPORT.summary.high,   color: "text-red-500"     },
            { label: "Medium Risk",  value: REPORT.summary.medium, color: "text-amber-500"   },
            { label: "Low Risk",     value: REPORT.summary.low,    color: "text-orange-500"  },
            { label: "Clean",        value: REPORT.summary.clean,  color: "text-emerald-600" },
          ].map(s => (
            <div key={s.label} className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
              <div className={`text-4xl font-semibold tracking-tight ${s.color}`}>{s.value}</div>
              <div className="text-gray-400 text-xs mt-2">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Tab Switcher */}
        <div className="flex gap-1 mb-6 bg-gray-100 rounded-xl p-1 w-fit">
          {[{ id: "cases", label: "Case View" }, { id: "matrix", label: "Signal Matrix" }].map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.id ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-800"}`}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Case View */}
        {activeTab === "cases" && (
          <div className="grid grid-cols-5 gap-5">
            <div className="col-span-2 space-y-2">
              <p className="text-xs text-gray-400 uppercase tracking-wider px-1 mb-3">
                {REPORT.cases.length} cases · priority order
              </p>
              {REPORT.cases.map((cas, i) => (
                <CaseRow key={cas.caseId} c={cas} isSelected={i === selected} onClick={() => setSelected(i)} />
              ))}
            </div>

            <div className="col-span-3 space-y-4">
              {/* Detail card */}
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
                <div className="flex items-start justify-between gap-4 mb-6">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2.5">
                      <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${cfg.pill}`}>{c.verdict}</span>
                      <span className="text-xs text-gray-400">{c.action}</span>
                    </div>
                    <p className="text-gray-800 font-medium text-sm break-all">{c.url}</p>
                    <p className="text-gray-400 text-xs font-mono mt-1.5">{c.caseId}</p>
                  </div>
                  <ScoreArc score={c.combinedScore} verdict={c.verdict} />
                </div>

                <div className="grid grid-cols-2 gap-x-8 gap-y-3">
                  {Object.entries(c.analyzers).map(([name, data]) => (
                    <AnalyzerBar key={name} name={name} data={data} />
                  ))}
                </div>

                <div className="mt-5 pt-4 border-t border-gray-50 flex flex-wrap gap-1.5">
                  {c.firedSignals.map(s => (
                    <span key={s} className="text-xs text-gray-500 bg-gray-50 border border-gray-200 px-2.5 py-0.5 rounded-full font-mono">{s}</span>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wider mb-3">Findings</p>
                <Findings analyzers={c.analyzers} />
              </div>
            </div>
          </div>
        )}

        {/* Matrix View */}
        {activeTab === "matrix" && (
          <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
            <div className="px-6 py-3.5 border-b border-gray-50 bg-gray-50/50">
              <div className="grid grid-cols-7 gap-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                <div className="col-span-2">Deployment</div>
                <div className="text-center">Score</div>
                <div className="text-center">Forms</div>
                <div className="text-center">Brands</div>
                <div className="text-center">Creds</div>
                <div className="text-center">Title</div>
              </div>
            </div>
            <div className="divide-y divide-gray-50">
              {REPORT.cases.map((cas, i) => {
                const vcfg = VERDICT_CONFIG[cas.verdict];
                const domain = cas.url.replace("https://", "").replace(/\/$/, "");
                return (
                  <button key={cas.caseId} onClick={() => { setSelected(i); setActiveTab("cases"); }}
                    className="w-full px-6 py-4 hover:bg-gray-50/60 transition-colors text-left">
                    <div className="grid grid-cols-7 gap-4 items-center">
                      <div className="col-span-2 flex items-center gap-3 min-w-0">
                        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${vcfg.dot}`} />
                        <div className="min-w-0">
                          <p className="text-sm text-gray-700 font-medium truncate">{domain}</p>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${vcfg.pill}`}>{cas.verdict}</span>
                        </div>
                      </div>
                      <div className={`text-center text-lg font-semibold tabular-nums ${vcfg.scoreText}`}>{cas.combinedScore}</div>
                      {["forms", "brands", "credentials", "title"].map(a => {
                        const score = cas.analyzers[a]?.score ?? 0;
                        const av = cas.analyzers[a]?.verdict ?? "clean";
                        const vc = ANALYZER_VERDICT_COLOR[av] || ANALYZER_VERDICT_COLOR.clean;
                        return (
                          <div key={a} className="text-center">
                            <span className={`text-sm font-semibold tabular-nums ${vc.text}`}>{score}</span>
                            <div className="mt-1 mx-auto w-10 h-1 bg-gray-100 rounded-full overflow-hidden">
                              <div className={`h-full ${vc.bar} rounded-full`} style={{ width: `${score}%` }} />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
