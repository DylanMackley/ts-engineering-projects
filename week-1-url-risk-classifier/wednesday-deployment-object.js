//=============================================
// Week 1 - Wednesday → Stage 4
// Objective: Model deployment data as objects
// & Connect Monday's detector to create deployments
// T&S Use Case: Structuring threat data properly
// so it can be stored, retrieved, and acted on
//=============================================

// --- KEYWORDS FROM MONDAY ---
const suspiciousKeywords = [
"login", "verify", "secure", "account", "update",
"confirm", "password", "signin", "banking", "authentication"
];

// --- checkURL FROM MONDAY ---
function checkURL(url) {
if (typeof url !== "string") return null;
const lowercased = url.toLowerCase();
let matches = [];
for (let i = 0; i < suspiciousKeywords.length; i++) {
    if (lowercased.includes(suspiciousKeywords[i])) {
    matches.push(suspiciousKeywords[i]);
    }
}
return matches;
}

// --- WEDNESDAY'S DEPLOYMENT OBJECT ---
// A deployment object that holds all relevant 
// information about one flagged deployment
const deployment = {
    url: "secure-login-verify.vercel.app",
    reportedAt: new Date().toISOString(),
    matchedKeywords: ["login", "verify", "secure"],
    matchCount: 3,
    riskLevel: "High",
    status: "Pending Review",

// Method - A function that belongs to this object
// this.matchCount refers to the matchCount above
getSummary: function() {
    return `URL: ${this.url} | Risk: ${this.riskLevel} | Matches: ${this.matchCount} | Status: ${this.status}`;
},

// Method that decides the risk level based on match count
calculateRisk: function() {
    if (this.matchCount >= 3) {
    this.riskLevel = "high";
    } else if (this.matchCount >= 1) {
    this.riskLevel = "medium";
    } else {
    this.riskLevel = "low";
    }
    return this.riskLevel;
}
};

console.log("Deployment Object:", deployment);
console.log("Summary", deployment.getSummary());
console.log("Risk Level", deployment.calculateRisk());

// An array of deployment objects
// Each one will be structured the same way
const deployments = [
    {
        url: "secure-login-verify.vercel.app",
        reportedAt: new Date().toISOString(),
        matchedKeywords: ["login", "verify", "secure"],
        matchCount: 3,
        riskLevel: "high",
        status: "Pending_Review"
    },
    { url: "paypal-confirm-identity.vercel.app",
        reportedAt: new Date().toISOString(),
        matchedKeywords: ["confirm"],
        matchCount: 1,
        riskLevel: "medium",
        status: "Pending_Review"
    },
    {
        url: "my-portfolio.vercel.app",
        reportedAt: new Date().toISOString(),
        matchedKeywords: [],
        matchCount: 0,
        riskLevel: "low",
        status: "Cleared"

    }
];

console.log("/nAll Deployments:", deployments);
deployments.forEach(d => console.log(d.url, "| Risk:", d.riskLevel ));

// A factory function - it creates and returns 
// a new deployment object every time you call it
function createDeployment(url, matchedKeywords){
    const matchCount = matchedKeywords.length;

    // Automatically calculates risks based on matchcount
    let riskLevel;
    if (matchCount >= 3) {
        riskLevel = "High";
    } else if (matchCount >= 1) {
        riskLevel = "Medium";
    } else {
        riskLevel = "Low";
    }
    return {
        url: url,
        reportedAt: new Date().toISOString(),
        matchedKeywords: matchedKeywords,
        matchCount: matchCount,
        riskLevel: riskLevel,
        status: "Pending Review",
        
        // Method to get a summary
        getSummary: function() {
            return `URL: ${this.url} | Risk: ${this.riskLevel} | Matches: ${this.matchCount} | Status: ${this.status}`;
        }
    };
}

// --- STAGE 4: COMBINE MONDAY + WEDNESDAY ---
// Scan a URL and immediately turn it into a properly structured deployment object
function scanAndCreate(url) {
    const matchedKeywords = checkURL(url);
    return createDeployment(url, matchedKeywords);
}

// Test the full pipeline
const testURLs = [
    "password-reset-urgent.vercel.app",
    "creative-agency-2024.vercel.app",
    "account-update-banking.vercel.app"
];

console.log("\n--- Full Pipeline Test ---");
testURLs.forEach(url => {
    const deployment = scanAndCreate(url);
    console.log(deployment.getSummary());
});


// Test factory functions 
const dep1 = createDeployment("signin-apple-id-locked.vercel.app", ["signin"]);
const dep2 = createDeployment("account-update-banking.vercel.app", ["account", "update", "banking"]);
const dep3 = createDeployment("restaurant-menu-site.vercel.app", []);

console.log("/n--- Created Deployments ---");
console.log(dep1.getSummary()); 
console.log(dep2.getSummary());
console.log(dep3.getSummary());
