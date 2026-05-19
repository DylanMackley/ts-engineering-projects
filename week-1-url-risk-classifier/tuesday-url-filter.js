//=========================================
// Week 1 - Tuesday
// Objective: Process and filter muliptle URLs
// T&S use case: Batch scanning list of suspicious deployments
//=========================================

// --- DATASET ---
// Simulating a batch of URLs to be reviewed
// In week 2 this list will come froma real API
const urLsForReview = [
"secure-login-verify.vercel.app",
"my-portfolio.vercel.app",
"account-update-banking.vercel.app",
"johns-design-studio.vercel.app",
"paypal-confirm-identity.vercel.app",
"creative-agency-2024.vercel.app",
"signin-apple-id-locked.vercel.app",
"restaurant-menu-site.vercel.app",
"password-reset-urgent.vercel.app",
"startup-landing-page.vercel.app"
];

console.log("Total URLs for review:", urLsForReview.length);

// --- REUSING MONDAY'S DETECTION LOGIC ---
// Same keywords, same logic - now processing a whole list

const suspiciousKeywords = [
"login", "verify", "secure", "account", "update",
"confirm", "password", "signin", "banking", "authentication"
];

function checkURL(url) {
if (typeof url !== "string") {
    console.log("Error: input must be a string");
    return null;
}

const lowercased = url.toLowerCase();
let matches = [];

for (let i = 0; i < suspiciousKeywords.length; i++) {
    if (lowercased.includes(suspiciousKeywords[i])) {
    matches.push(suspiciousKeywords[i]);
    }
}

return {
    url: url,
    isSuspicious: matches.length > 0,
    matchedKeywords: matches,
    matchCount: matches.length
};
}

// --- PROCESSING THE URL LIST ---
// map() runs checkURL in every URL in the array
// It transforms each URL string into full result object
// Input:  ["url1", "url2', "url3"]
// Output: [{result1}, {result2}, result3}]
const allResults = urLsForReview.map(url1 => checkURL(url1));

console.log("/n--- All Results ---"); 
console.log(allResults);

// filter() keeps all results where isSuspicious is true
// it removes everything that doesnt meet the condition 
const suspiciousOnly = allResults.filter(result => result.isSuspicious === true);

console.log("/n --- Suspicious URLs Only ---");
console.log(suspiciousOnly);

// filter() again - this time to only keep the clean ones
const cleanOnly = allResults.filter(result => result.isSuspicious === false);

console.log("/n --- Clean URLs ---");
console.log(cleanOnly);

// find() gets the first suspicious result it finds
// Useful when you need to pull one example 
const firstThreat = allResults.find(result => result.isSuspicious === true);

console.log("/n --- First Threat Found ---");
console.log(firstThreat);

// some() checks if atleast one URL is suspicious
// Returns true or false - good for quick checks
const anyThreats = allResults.some(result => result.isSuspicious === true);

console.log("/n --- Any Threats Detected? ---");
console.log(anyThreats);

// --- THE ACTUAL TOOL --
// a batch scanner that processes any list of URLs 
// and reurns a structured triage report

function batchScan(urls) {

    // Make sure we recieved an array
    if (!Array.isArray(urls)) {
        console.log("Error: input must be an array");
        return null;
    }

// Run every URL through the detector
const results = urls.map(url => checkURL(url));

// Seperate into risk groups
const suspicious = results.filter(r => r.isSuspicious === true);
const clean = results.filter(r => r.isSuspicious === false);

// Sort suspicious by match count - Highest risk first
const prioritized = suspicious.sort((a, b) => b.matchCount - a.matchCount);

// Build a triage report
const report = {
    totalScanned: urls.length,
    totalSuspicious: suspicious.length,
    totalClean: clean.length,
    flagRate: ((suspicious.length / urls.length) * 100).toFixed(1) + "%",
    highestRisk: prioritized[0] || null, 
    suspiciousURls: prioritized,
    cleanURLs: clean
};

return report;
}

// --- RUN THE BATCH SCAN ---
console.log("/n --- Triage Scan Report ---");
const report = batchScan(urLsForReview);
console.log("Total Scanned:", report.totalScanned);
console.log("Total Suspicious:", report.totalSuspicious);
console.log("Total Clean:", report.totalClean);
console.log("Flag Rate:", report.flagRate);
console.log("/nHighest Risk URL");
console.log(report.highestRisk);
console.log("n/All Suspicious URLs by Risk Level");
console.log(report.suspiciousURls);








