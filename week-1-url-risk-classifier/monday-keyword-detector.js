//=============================================
// Week 1 - Monday
// Objective: Detect suspicious keywords in a URL
// T&S use case: First signal in phishing detection
//=============================================

// --- VARIABLES AND DATA TYPES ---

// String: A single URL we want to check
const testURL = "secure-login-verify.vercel.app";

// Boolean: Is it suspicious? We dont know yet
let isSuspicious = false;

// Number: How many suspicious keywords are found?
let matchCount = 0;

// Array: Common keywords found in phishing URLs
const suspiciousKeywords = [
"login",
"verify",
"secure",
"account",
"update",
"confirm",
"password",
"signin",
"banking",
"authentication",
];

// Log them so you can see what you're working with
console.log("URL being checked:", testURL);
console.log("Keywords to watch for:", suspiciousKeywords);
console.log("Suspicious so far?", isSuspicious);

// --- COMPARISONS ---

// Convert URL to lowercase first
// Why: "Login" and "login" and "LOGIN" are all the same threat
// .toLowerCase() is a string method - it returns a new lowercase string
const lowercaseURL = testURL.toLowerCase();

// .includes() checks if one string lives inside another
// It returns true or false - thats a Boolean
const containsLogin = lowercaseURL.includes("login");
const containsVerify = lowercaseURL.includes("verify");
const containsPortfolio = lowercaseURL.includes("portfolio");

console.log("Contains 'login'?", containsLogin); // true
console.log("Contains 'verify'?", containsVerify); // true
console.log("Contains 'portfolio'?", containsPortfolio); // false

// --- CONDITIONALS ---

// If the URL contains "login",update our variables
if (containsLogin === true) {
  isSuspicious = true;
  matchCount = matchCount + 1;
  console.log("⚠️ Match found: 'login'");
}
if (containsVerify === true) {
  isSuspicious = true;
  matchCount = matchCount + 1;
  console.log("⚠️ Match found: 'verify'");
}
// Final decision
if (isSuspicious === true) {
  console.log("🔴 VERDICT: Suspicious URL detected");
  console.log("Total keyword matches:", matchCount);
} else {
  console.log("🟢 VERDICT: URL is clean");
}

// --- THE ACTUAL TOOL ---
// Everything above was learning the pieces
// This function puts it all together cleanly

function checkURL(url) {
  // Input validation - make sure we actually received a string
  if (typeof url !== "string") {
    console.log("Error: input must be a string");
    return null;
  }

  const lowercased = url.toLowerCase();
  let matches = [];

  // Loop through every keyword and check if it appears in the URL
  for (let i = 0; i < suspiciousKeywords.length; i++) {
    if (lowercased.includes(suspiciousKeywords[i])) {
      matches.push(suspiciousKeywords[i]);
    }
  }

  // Build a result object with all the information
  const result = {
    url: url,
    isSuspicious: matches.length > 0,
    matchedKeywords: matches,
    matchCount: matches.length,
  };

  return result;
}

// --- TEST YOUR FUNCTION ---
console.log("\n--- Running checkURL tests ---\n");

console.log(checkURL("secure-login-verify.vercel.app"));
console.log(checkURL("my-portfolio.vercel.app"));
console.log(checkURL("account-update-banking.vercel.app"));
console.log(checkURL("johns-design-studio.vercel.app"));
