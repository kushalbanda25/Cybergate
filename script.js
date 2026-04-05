/**
 * Cyber Gate – Security Analysis Platform
 * script.js
 *
 * Fully functional IDS engine with:
 * 1. Login / Logout with input validation
 * 2. Signature-based detection (XSS, SQLi, Path Traversal, Cmd Injection, LFI, XXE)
 * 3. Anomaly-based detection (length, special chars, entropy)
 * 4. Proper input sanitization
 * 5. Username field attack blocking
 * 6. Rate limiting (anti-DoS)
 * 7. URL decoding / normalization
 * 8. Defense-in-depth simulation (5 layers)
 * 9. Forensic activity logging
 * 10. False-positive handling
 * 11. Dynamic payload analysis (analyzes actual content, not just button)
 * 12. MITRE ATT&CK mapping
 * 13. Navigation guard for analysis.html
 */


// ─────────────────────────────────────────
// IDS DETECTION RULES (Signature-Based)
// Each rule: regex, score, description,
// attack type, MITRE technique ID
// ─────────────────────────────────────────
const IDS_RULES = [
    // XSS rules
    { id: "R01", pattern: /<script[\s>]/i,          score: 50, desc: "Script tag detected",                    type: "XSS",                mitre: "T1059.007" },
    { id: "R02", pattern: /alert\s*\(/i,            score: 30, desc: "JavaScript alert() call found",          type: "XSS",                mitre: "T1059.007" },
    { id: "R03", pattern: /onerror\s*=/i,           score: 40, desc: "HTML event handler injection (onerror)", type: "XSS",                mitre: "T1059.007" },
    { id: "R04", pattern: /onload\s*=/i,            score: 40, desc: "HTML event handler injection (onload)",  type: "XSS",                mitre: "T1059.007" },
    { id: "R05", pattern: /document\.(cookie|write)/i, score: 45, desc: "DOM manipulation attempt",           type: "XSS",                mitre: "T1059.007" },
    { id: "R06", pattern: /javascript\s*:/i,        score: 45, desc: "JavaScript URI scheme detected",        type: "XSS",                mitre: "T1059.007" },
    { id: "R07", pattern: /<img[^>]+on\w+\s*=/i,    score: 40, desc: "Image tag with event handler",          type: "XSS",                mitre: "T1059.007" },
    { id: "R08", pattern: /<iframe/i,               score: 45, desc: "Iframe injection attempt",              type: "XSS",                mitre: "T1059.007" },

    // SQL Injection rules
    { id: "R10", pattern: /'\s*OR\s*/i,             score: 45, desc: "SQL OR operator manipulation",          type: "SQL Injection",      mitre: "T1190" },
    { id: "R11", pattern: /1\s*=\s*1/i,             score: 35, desc: "SQL always-true condition (1=1)",       type: "SQL Injection",      mitre: "T1190" },
    { id: "R12", pattern: /UNION\s+SELECT/i,        score: 50, desc: "SQL UNION-based data extraction",       type: "SQL Injection",      mitre: "T1190" },
    { id: "R13", pattern: /--\s*$/m,                score: 30, desc: "SQL comment used to truncate query",    type: "SQL Injection",      mitre: "T1190" },
    { id: "R14", pattern: /DROP\s+TABLE/i,          score: 50, desc: "SQL DROP TABLE command",                type: "SQL Injection",      mitre: "T1190" },
    { id: "R15", pattern: /;\s*SELECT\s/i,          score: 45, desc: "Stacked SQL query detected",            type: "SQL Injection",      mitre: "T1190" },
    { id: "R16", pattern: /'\s*AND\s*/i,            score: 35, desc: "SQL AND operator manipulation",         type: "SQL Injection",      mitre: "T1190" },

    // Path Traversal rules
    { id: "R20", pattern: /\.\.\//,                 score: 40, desc: "Directory traversal (../)",             type: "Path Traversal",     mitre: "T1083" },
    { id: "R21", pattern: /\.\.\\/,                 score: 40, desc: "Directory traversal (..\\)",            type: "Path Traversal",     mitre: "T1083" },
    { id: "R22", pattern: /%2e%2e(%2f|%5c)/i,       score: 45, desc: "URL-encoded directory traversal",       type: "Path Traversal",     mitre: "T1083" },

    // LFI rules
    { id: "R25", pattern: /\/etc\/passwd/i,         score: 50, desc: "Access to /etc/passwd attempted",       type: "LFI",                mitre: "T1005" },
    { id: "R26", pattern: /\/etc\/shadow/i,         score: 50, desc: "Access to /etc/shadow attempted",       type: "LFI",                mitre: "T1005" },
    { id: "R27", pattern: /\/proc\/self/i,          score: 45, desc: "Access to /proc/self attempted",        type: "LFI",                mitre: "T1005" },
    { id: "R28", pattern: /\.htaccess/i,            score: 40, desc: "Access to .htaccess attempted",         type: "LFI",                mitre: "T1005" },

    // Command Injection rules
    { id: "R30", pattern: /;\s*(ls|cat|rm|wget|curl|whoami|id|uname)\b/i, score: 50, desc: "OS command after separator",   type: "Command Injection", mitre: "T1059" },
    { id: "R31", pattern: /\|\s*(ls|cat|rm|wget|curl|whoami|id|uname)\b/i,score: 50, desc: "Pipe to OS command",           type: "Command Injection", mitre: "T1059" },
    { id: "R32", pattern: /`[^`]+`/,                score: 45, desc: "Backtick command execution",            type: "Command Injection",  mitre: "T1059" },
    { id: "R33", pattern: /\$\([^)]+\)/,            score: 45, desc: "Sub-shell command execution $(...)",    type: "Command Injection",  mitre: "T1059" },
    { id: "R34", pattern: /&&\s*\w+/,               score: 40, desc: "Chained command via &&",                type: "Command Injection",  mitre: "T1059" },

    // XXE rules
    { id: "R40", pattern: /<!ENTITY/i,              score: 50, desc: "XML External Entity declaration",       type: "XXE",                mitre: "T1059.009" },
    { id: "R41", pattern: /<!DOCTYPE[^>]*\[/i,      score: 40, desc: "DOCTYPE with inline DTD",               type: "XXE",                mitre: "T1059.009" },
    { id: "R42", pattern: /SYSTEM\s*["']/i,         score: 45, desc: "SYSTEM keyword in entity definition",   type: "XXE",                mitre: "T1059.009" }
];


// ─────────────────────────────────────────
// ATTACK PRESETS
// Pre-filled payloads, explanations,
// prevention tips, and MITRE references
// ─────────────────────────────────────────
const ATTACKS = {
    xss: {
        label: "Cross-Site Scripting (XSS)",
        payload: "<script>alert('XSS')</script>",
        whyDetected: "The payload contains a <script> tag and an alert() call. These are classic signs of a reflected XSS attack where an attacker injects executable JavaScript into a web page to steal cookies, hijack sessions, or deface the site.",
        prevention: [
            "Encode all user input before rendering (convert < to &lt;, > to &gt;).",
            "Use a Content Security Policy (CSP) header to restrict executable scripts.",
            "Use a sanitization library like DOMPurify on any HTML input.",
            "Implement HttpOnly and Secure flags on session cookies."
        ],
        mitre: "MITRE ATT&CK T1059.007 — Command and Scripting Interpreter: JavaScript"
    },
    sqli: {
        label: "SQL Injection",
        payload: "' OR '1'='1' --",
        whyDetected: "The payload contains a single quote (') followed by OR and a trivially true condition (1=1). The trailing -- comments out the rest of the SQL query. This bypasses authentication by making the WHERE clause always TRUE.",
        prevention: [
            "Always use Parameterized Queries (Prepared Statements) instead of string concatenation.",
            "Use an ORM (like Hibernate or Sequelize) to handle database queries safely.",
            "Validate and restrict the type, length, and format of all user inputs.",
            "Apply least-privilege database permissions to the application account."
        ],
        mitre: "MITRE ATT&CK T1190 — Exploit Public-Facing Application"
    },
    path: {
        label: "Path Traversal",
        payload: "../../etc/passwd",
        whyDetected: "The payload uses '../' sequences to climb up the directory tree and access /etc/passwd, a sensitive system file that lists user accounts. This is a directory traversal attack.",
        prevention: [
            "Validate file paths and reject any input containing '../' or absolute paths.",
            "Use a whitelist of allowed file names or directories.",
            "Run the application with the least possible file system permissions.",
            "Canonicalize paths before use and compare against allowed base directory."
        ],
        mitre: "MITRE ATT&CK T1083 — File and Directory Discovery"
    },
    cmd: {
        label: "Command Injection",
        payload: "; ls -la /etc",
        whyDetected: "The semicolon (;) is a command separator in Unix/Linux. An attacker appends their own OS command after a legitimate one, causing the server to execute arbitrary system commands.",
        prevention: [
            "Never pass user input directly to shell functions (exec, system, popen).",
            "Use language built-in APIs instead of shell commands where possible.",
            "Strip or reject special characters like ; & | ` $ from user input.",
            "Run the application in a sandboxed environment with restricted OS access."
        ],
        mitre: "MITRE ATT&CK T1059 — Command and Scripting Interpreter"
    },
    lfi: {
        label: "Local File Inclusion (LFI)",
        payload: "../../../../etc/shadow",
        whyDetected: "The payload uses directory traversal to reach /etc/shadow, a file containing hashed passwords of all system users. This is a classic LFI attempt to exfiltrate sensitive data.",
        prevention: [
            "Do not use user-supplied input directly in file include/require calls.",
            "Disable allow_url_include in php.ini if using PHP.",
            "Use a fixed mapping (switch-case or config lookup) instead of dynamic file paths.",
            "Implement file access controls and chroot jails."
        ],
        mitre: "MITRE ATT&CK T1005 — Data from Local System"
    },
    xxe: {
        label: "XML External Entity (XXE)",
        payload: '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY f SYSTEM "file:///etc/passwd">]><x>&f;</x>',
        whyDetected: "The payload defines an XML External Entity that references a local file via SYSTEM keyword. When the XML parser processes &f;, it reads and embeds the contents of /etc/passwd into the response.",
        prevention: [
            "Disable DTD (Document Type Definitions) processing in your XML parser.",
            "Disable external entity loading (set FEATURE_EXTERNAL_GENERAL_ENTITIES = false).",
            "Use JSON instead of XML for data exchange where possible.",
            "Keep XML parser libraries updated to latest patched versions."
        ],
        mitre: "MITRE ATT&CK T1059.009 — Command and Scripting Interpreter: Cloud API"
    },
    safe: {
        label: "Safe / Normal Input",
        payload: "john_doe_2024",
        whyDetected: "No malicious patterns were found. This input is a normal alphanumeric string with no special characters, no injection sequences, and no anomalous features.",
        prevention: [
            "Continue enforcing input length limits.",
            "Keep IDS signature rules updated with new attack patterns.",
            "Log all inputs for future auditing and baseline analysis.",
            "Periodically review logs for emerging threats."
        ],
        mitre: "N/A — No attack detected"
    }
};


// ─────────────────────────────────────────
// USERNAME VALIDATION REGEX
// Only allows: letters, numbers, dots,
// underscores, hyphens, and @ for emails
// ─────────────────────────────────────────
const USERNAME_SAFE_REGEX = /^[a-zA-Z0-9._@\-]+$/;


// ─────────────────────────────────────────
// STATE VARIABLES
// ─────────────────────────────────────────
let currentTarget = "password";      // Default target is password (Bug #2 fix)
let selectedAttack = null;           // Which attack button is selected
let rateLimitTimestamps = [];        // Timestamps for rate limiting
const RATE_LIMIT_COUNT = 5;          // Max attacks allowed
const RATE_LIMIT_WINDOW_MS = 2000;   // Within this time window (2 seconds)


// ─────────────────────────────────────────
// TARGET SETUP HANDLER
// Configures the simulated target application
// with user-provided credentials and launches
// the IDS analysis dashboard
// ─────────────────────────────────────────
function handleLogin() {
    var targetUser = document.getElementById("email").value.trim();
    var targetPass = document.getElementById("password").value.trim();
    var errMsg = document.getElementById("login-error");

    // Check empty fields
    if (!targetUser || !targetPass) {
        errMsg.textContent = "Please configure both target username and password.";
        errMsg.style.display = "block";
        return;
    }

    // Block attacks in target setup fields (keep them clean)
    var dangerousPatterns = [/<script/i, /onerror\s*=/i, /alert\s*\(/i, /'\s*OR\s*/i, /UNION\s+SELECT/i, /\.\.\//i, /<!ENTITY/i, /;\s*(ls|cat|rm)/i];
    for (var i = 0; i < dangerousPatterns.length; i++) {
        if (dangerousPatterns[i].test(targetUser) || dangerousPatterns[i].test(targetPass)) {
            errMsg.textContent = "Target credentials should be clean — attack payloads are injected from the dashboard.";
            errMsg.style.display = "block";
            return;
        }
    }

    errMsg.style.display = "none";

    // Save target config to session (persists across page navigations)
    sessionStorage.setItem("ids_logged_in", "true");
    sessionStorage.setItem("ids_target_user", targetUser);
    sessionStorage.setItem("ids_target_pass", targetPass);

    // Hide setup, show main app
    document.getElementById("login-page").style.display = "none";
    document.getElementById("main-page").style.display = "block";

    // Populate the simulated target form with configured credentials
    document.getElementById("sim-username").value = targetUser;
    document.getElementById("sim-password").value = "";

    // Set default target button state
    document.getElementById("btn-username").classList.remove("active");
    document.getElementById("btn-password").classList.add("active");
}


// ─────────────────────────────────────────
// LOGOUT / RESET HANDLER
// Clears everything: target config, logs,
// session — returns to a fresh setup page
// ─────────────────────────────────────────
function handleLogout() {
    sessionStorage.removeItem("ids_logged_in");
    sessionStorage.removeItem("ids_activity_log");
    sessionStorage.removeItem("ids_target_user");
    sessionStorage.removeItem("ids_target_pass");

    document.getElementById("main-page").style.display = "none";
    document.getElementById("login-page").style.display = "flex";

    document.getElementById("email").value = "";
    document.getElementById("password").value = "";

    resetAll();
}


// ─────────────────────────────────────────
// SET TARGET FIELD
// Switches between Username and Password
// ─────────────────────────────────────────
function setTarget(field) {
    currentTarget = field;
    document.getElementById("btn-username").classList.toggle("active", field === "username");
    document.getElementById("btn-password").classList.toggle("active", field === "password");
}


// ─────────────────────────────────────────
// SELECT ATTACK TYPE
// Highlights clicked button, loads payload
// ─────────────────────────────────────────
function selectAttack(btn, attackKey) {
    document.querySelectorAll(".atk-btn").forEach(function (b) {
        b.classList.remove("selected");
    });
    btn.classList.add("selected");
    selectedAttack = attackKey;

    var attack = ATTACKS[attackKey];
    if (attack) {
        var payload = attack.payload;
        
        // If 'Safe Input' is selected, use the password from the target setup
        if (attackKey === 'safe') {
            payload = sessionStorage.getItem("ids_target_pass") || "safe_password_123";
        }

        document.getElementById("payload-input").value = payload;
        // Mirror payload into the target password field
        document.getElementById("sim-password").value = payload;
    }
}


// ─────────────────────────────────────────
// NORMALIZE / DECODE PAYLOAD (Bug #14 fix)
// Decodes URL-encoded, double-encoded, and
// common evasion techniques before analysis
// ─────────────────────────────────────────
function normalizePayload(input) {
    var result = input;

    // Decode URL encoding (up to 3 passes for double/triple encoding)
    for (var pass = 0; pass < 3; pass++) {
        try {
            var decoded = decodeURIComponent(result);
            if (decoded === result) break;
            result = decoded;
        } catch (e) {
            break;
        }
    }

    return result;
}


// ─────────────────────────────────────────
// CALCULATE ENTROPY (Bug #5 anomaly)
// Shannon entropy of a string — higher
// values indicate more randomness
// ─────────────────────────────────────────
function calculateEntropy(str) {
    if (str.length === 0) return 0;

    var freq = {};
    for (var i = 0; i < str.length; i++) {
        var ch = str[i];
        freq[ch] = (freq[ch] || 0) + 1;
    }

    var entropy = 0;
    var len = str.length;
    for (var ch in freq) {
        var p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * 100) / 100;
}


// ─────────────────────────────────────────
// COUNT SPECIAL CHARACTERS (Bug #5 anomaly)
// ─────────────────────────────────────────
function countSpecialChars(str) {
    var count = 0;
    var specials = "<>'\";|&`$(){}[]!@#%^*\\/:?";
    for (var i = 0; i < str.length; i++) {
        if (specials.indexOf(str[i]) !== -1) {
            count++;
        }
    }
    return count;
}


// ─────────────────────────────────────────
// FALSE-POSITIVE CHECK (Bug #12 fix)
// Checks if suspicious characters appear
// in a benign context (e.g., "hello <3")
// ─────────────────────────────────────────
function isFalsePositive(payload, triggeredRules) {
    // If only one low-score rule triggered and the payload looks benign
    if (triggeredRules.length === 1 && triggeredRules[0].score <= 35) {
        // Check for common false positives
        var fpPatterns = [
            /^[a-zA-Z\s]+<3$/,                    // "hello <3" (heart emoji shorthand)
            /^[a-zA-Z0-9\s.,!?'-]+$/,             // Plain English text
            /^\d+\s*=\s*\d+$/                      // Simple math "1 = 1"
        ];
        for (var i = 0; i < fpPatterns.length; i++) {
            if (fpPatterns[i].test(payload.trim())) {
                return true;
            }
        }
    }
    return false;
}


// ─────────────────────────────────────────
// DETECT ATTACK TYPE DYNAMICALLY (Bug #13)
// Analyzes actual payload content instead
// of relying only on button selection
// ─────────────────────────────────────────
function detectAttackType(triggeredRules) {
    if (triggeredRules.length === 0) return "safe";

    // Count occurrences of each attack type
    var typeCounts = {};
    var maxCount = 0;
    var dominantType = "Unknown";

    for (var i = 0; i < triggeredRules.length; i++) {
        var t = triggeredRules[i].type;
        if (t === "Anomaly") continue;
        typeCounts[t] = (typeCounts[t] || 0) + 1;
        if (typeCounts[t] > maxCount) {
            maxCount = typeCounts[t];
            dominantType = t;
        }
    }

    return dominantType;
}

// Map detected type string to ATTACKS key
function typeToKey(typeStr) {
    var map = {
        "XSS": "xss",
        "SQL Injection": "sqli",
        "Path Traversal": "path",
        "Command Injection": "cmd",
        "LFI": "lfi",
        "XXE": "xxe"
    };
    return map[typeStr] || "safe";
}


// ─────────────────────────────────────────
// ANALYZE PAYLOAD (IDS Engine Core)
// Runs signature + anomaly detection,
// decodes input, checks false positives
// Bug #1, #5, #9, #12, #13, #14 fixes
// ─────────────────────────────────────────
function analyzePayload(rawPayload) {
    // Step 1: Normalize/decode the payload
    var payload = normalizePayload(rawPayload);

    var score = 0;
    var triggeredRules = [];

    // Step 2: Signature-based detection
    for (var i = 0; i < IDS_RULES.length; i++) {
        var rule = IDS_RULES[i];
        if (rule.pattern.test(payload)) {
            score += rule.score;
            triggeredRules.push({
                id: rule.id,
                desc: rule.desc,
                type: rule.type,
                mitre: rule.mitre
            });
        }
    }

    // Step 3: Anomaly-based detection
    var anomalies = [];

    // 3a. Length check
    if (payload.length > 100) {
        score += 15;
        anomalies.push({ id: "A01", desc: "Input is very long (" + payload.length + " chars, threshold: 100)", type: "Anomaly" });
    } else if (payload.length > 50) {
        score += 8;
        anomalies.push({ id: "A02", desc: "Input is moderately long (" + payload.length + " chars, threshold: 50)", type: "Anomaly" });
    }

    // 3b. Special character density
    var specialCount = countSpecialChars(payload);
    var specialRatio = payload.length > 0 ? (specialCount / payload.length) : 0;
    if (specialRatio > 0.4) {
        score += 15;
        anomalies.push({ id: "A03", desc: "High special character density (" + Math.round(specialRatio * 100) + "%, " + specialCount + " special chars)", type: "Anomaly" });
    } else if (specialRatio > 0.2) {
        score += 8;
        anomalies.push({ id: "A04", desc: "Moderate special character density (" + Math.round(specialRatio * 100) + "%, " + specialCount + " special chars)", type: "Anomaly" });
    }

    // 3c. Entropy check
    var entropy = calculateEntropy(payload);
    if (entropy > 4.5) {
        score += 10;
        anomalies.push({ id: "A05", desc: "High entropy (" + entropy + " bits/char) — possible obfuscated payload", type: "Anomaly" });
    }

    // Add anomalies to triggered rules
    triggeredRules = triggeredRules.concat(anomalies);

    // Step 4: False-positive check
    if (isFalsePositive(rawPayload, triggeredRules)) {
        score = 0;
        triggeredRules = [];
    }

    // Step 5: Dynamically detect the attack type from payload content
    var detectedType = detectAttackType(triggeredRules);

    // Cap at 100
    score = Math.min(score, 100);

    return {
        score: score,
        triggeredRules: triggeredRules,
        detectedType: detectedType,
        anomalies: anomalies,
        entropy: entropy,
        specialChars: specialCount,
        normalizedPayload: payload
    };
}


// ─────────────────────────────────────────
// SANITIZE INPUT (Bug #3 fix)
// Real sanitization: escape HTML, quotes,
// strip script tags, remove cmd separators,
// normalize slashes
// ─────────────────────────────────────────
function sanitize(input) {
    var result = input;

    // 1. Strip script tags and their content
    result = result.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "[SCRIPT_REMOVED]");
    result = result.replace(/<script[^>]*>/gi, "[SCRIPT_TAG_REMOVED]");

    // 2. Strip other dangerous tags
    result = result.replace(/<iframe[^>]*>[\s\S]*?<\/iframe>/gi, "[IFRAME_REMOVED]");
    result = result.replace(/<iframe[^>]*>/gi, "[IFRAME_TAG_REMOVED]");

    // 3. Remove event handlers from any remaining tags
    result = result.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, " [EVENT_HANDLER_REMOVED]");

    // 4. Escape HTML entities
    result = result.replace(/&/g, "&amp;");
    result = result.replace(/</g, "&lt;");
    result = result.replace(/>/g, "&gt;");

    // 5. Escape quotes
    result = result.replace(/"/g, "&quot;");
    result = result.replace(/'/g, "&#x27;");

    // 6. Remove command separators
    result = result.replace(/;/g, "[SEMICOLON_REMOVED]");
    result = result.replace(/\|/g, "[PIPE_REMOVED]");
    result = result.replace(/`/g, "[BACKTICK_REMOVED]");

    // 7. Normalize directory traversal
    result = result.replace(/\.\.\//g, "[PATH_BLOCKED]");
    result = result.replace(/\.\.\\/g, "[PATH_BLOCKED]");

    // 8. Escape forward slashes in suspicious contexts
    result = result.replace(/\/etc\//gi, "[SYSTEM_PATH_BLOCKED]");
    result = result.replace(/\/proc\//gi, "[SYSTEM_PATH_BLOCKED]");

    return result;
}


// ─────────────────────────────────────────
// DEFENSE-IN-DEPTH LAYERS (Bug #15 fix)
// Simulates 5 security layers and returns
// results for each layer
// ─────────────────────────────────────────
function runDefenseLayers(payload, analysisResult) {
    var layers = [];

    // Layer 1: Input Validation
    var hasInvalidChars = countSpecialChars(payload) > 0;
    layers.push({
        name: "Input Validation",
        status: hasInvalidChars ? "FLAGGED" : "PASSED",
        detail: hasInvalidChars
            ? "Input contains " + countSpecialChars(payload) + " special character(s)"
            : "Input contains only safe characters"
    });

    // Layer 2: WAF Signature Match
    var sigRules = analysisResult.triggeredRules.filter(function(r) { return r.type !== "Anomaly"; });
    layers.push({
        name: "WAF Signature Match",
        status: sigRules.length > 0 ? "BLOCKED" : "PASSED",
        detail: sigRules.length > 0
            ? sigRules.length + " signature rule(s) matched"
            : "No known attack signatures found"
    });

    // Layer 3: Anomaly Detection
    var anomalyRules = analysisResult.anomalies || [];
    layers.push({
        name: "Anomaly Detection",
        status: anomalyRules.length > 0 ? "FLAGGED" : "PASSED",
        detail: anomalyRules.length > 0
            ? anomalyRules.length + " anomaly indicator(s) triggered"
            : "No anomalous behaviour detected"
    });

    // Layer 4: Sanitization
    var sanitized = sanitize(payload);
    var wasModified = sanitized !== payload;
    layers.push({
        name: "Sanitization",
        status: wasModified ? "MODIFIED" : "CLEAN",
        detail: wasModified
            ? "Input was modified to neutralize dangerous content"
            : "Input required no sanitization"
    });

    // Layer 5: Rate Limiting
    var isRateLimited = checkRateLimit(true); // Dry-run check
    layers.push({
        name: "Rate Limiting",
        status: isRateLimited ? "THROTTLED" : "PASSED",
        detail: isRateLimited
            ? "Too many requests — rate limit exceeded"
            : "Request rate is within limits"
    });

    return layers;
}


// ─────────────────────────────────────────
// RATE LIMITING (Bug #8 fix)
// Blocks if more than RATE_LIMIT_COUNT
// injections within RATE_LIMIT_WINDOW_MS
// ─────────────────────────────────────────
function checkRateLimit(dryRun) {
    var now = Date.now();

    // Remove timestamps outside the window
    rateLimitTimestamps = rateLimitTimestamps.filter(function (ts) {
        return now - ts < RATE_LIMIT_WINDOW_MS;
    });

    if (rateLimitTimestamps.length >= RATE_LIMIT_COUNT) {
        return true; // Rate limited
    }

    if (!dryRun) {
        rateLimitTimestamps.push(now);
    }
    return false;
}


// ─────────────────────────────────────────
// ADD LOG ENTRY (Bug #11 fix)
// Forensic-quality log with timestamp,
// attack type, payload, target, decision,
// matched rules
// ─────────────────────────────────────────
function addLog(attackType, payload, target, decision, matchedRules) {
    var box = document.getElementById("log-box");
    var empty = box.querySelector(".log-empty");
    if (empty) empty.remove();

    var time = new Date().toLocaleTimeString("en-US", { hour12: false });
    var date = new Date().toLocaleDateString("en-US");
    var preview = payload.length > 25 ? payload.substring(0, 25) + "..." : payload;

    // Collect rule IDs
    var ruleIds = matchedRules.map(function (r) { return r.id; }).join(", ");
    if (!ruleIds) ruleIds = "None";

    var row = document.createElement("div");
    row.className = "log-row";
    row.innerHTML =
        '<span class="log-ts">[' + date + " " + time + ']</span> ' +
        '<span class="' + (decision === "BLOCKED" ? "log-blocked" : "log-allowed") + '">' + decision + '</span> ' +
        '<span>' + attackType + ' | Target: ' + target + ' | Payload: ' + preview + ' | Rules: ' + ruleIds + '</span>';

    box.prepend(row);

    // Persist log entry to sessionStorage so it survives page navigations
    var savedLogs = JSON.parse(sessionStorage.getItem("ids_activity_log") || "[]");
    savedLogs.unshift({
        date: date,
        time: time,
        decision: decision,
        attackType: attackType,
        target: target,
        preview: preview,
        ruleIds: ruleIds
    });
    sessionStorage.setItem("ids_activity_log", JSON.stringify(savedLogs));
}


// ─────────────────────────────────────────
// INJECT & ANALYZE (Main Function)
// Runs full IDS pipeline:
// 1. Rate limit check
// 2. Username field blocking
// 3. Payload analysis
// 4. Defense-in-depth layers
// 5. Forensic logging
// 6. Store results → analysis.html
// ─────────────────────────────────────────
function injectAndAnalyze() {
    var payload = document.getElementById("payload-input").value.trim();
    var statusMsg = document.getElementById("status-msg");

    if (!payload) {
        showStatus("Please enter a payload before injecting.", "error");
        return;
    }

    // Rate limiting check (Bug #8)
    if (checkRateLimit(false)) {
        showStatus("⚠ RATE LIMITED — Too many requests. Wait 2 seconds.", "error");
        addLog("Rate Limit", payload, currentTarget, "BLOCKED", [{ id: "RATE", desc: "Rate limit exceeded" }]);
        return;
    }

    // Run the IDS detection engine
    var analysis = analyzePayload(payload);

    // Dynamic attack type detection (Bug #13):
    // Use payload content analysis, not just which button was clicked
    var dynamicType = analysis.detectedType;
    var atkKey = (dynamicType !== "Unknown" && dynamicType !== "safe")
        ? typeToKey(dynamicType)
        : (selectedAttack || "safe");
    var atkData = ATTACKS[atkKey] || ATTACKS["safe"];

    // If safe input detected dynamically, use safe data
    if (analysis.score === 0) {
        atkKey = "safe";
        atkData = ATTACKS["safe"];
    }

    // Username field blocking (Bug #2)
    if (currentTarget === "username" && analysis.score > 0) {
        showStatus("⚠ BLOCKED — Attacks on the Username field are not allowed. Username accepts only safe alphanumeric input. Switch target to Password.", "error");

        // Still log it
        addLog(atkData.label, payload, "Username (BLOCKED)", "BLOCKED", analysis.triggeredRules);

        // Build result but mark as username-blocked
        var blockedResult = {
            attackType: atkData.label,
            target: "Username Field (Attack Blocked)",
            score: analysis.score,
            blocked: true,
            whyDetected: "Attack was injected into the USERNAME field, which only accepts safe alphanumeric input. In real systems, username fields are heavily validated (email format, length, character restrictions). Dangerous payloads like XSS, SQLi, or traversal attacks are rejected before processing.",
            rules: analysis.triggeredRules,
            prevention: [
                "Username fields should enforce strict format validation (e.g., email regex).",
                "Restrict allowed characters to alphanumeric, dots, underscores, and hyphens.",
                "Apply server-side validation and reject special characters.",
                "Use the Password field as the attack target for IDS simulation."
            ],
            originalPayload: payload,
            sanitizedPayload: sanitize(payload),
            decision: "BLOCKED",
            anomalies: analysis.anomalies,
            entropy: analysis.entropy,
            specialChars: analysis.specialChars,
            layers: runDefenseLayers(payload, analysis),
            mitre: atkData.mitre,
            timestamp: new Date().toISOString()
        };

        localStorage.setItem("ids_result", JSON.stringify(blockedResult));
        window.location.href = "analysis.html";
        return;
    }

    var blocked = analysis.score >= 30;

    // Show payload in simulated login form
    if (currentTarget === "username") {
        document.getElementById("sim-username").value = payload;
        document.getElementById("sim-password").value = "";
    } else {
        document.getElementById("sim-password").value = payload;
        document.getElementById("sim-username").value = "";
    }

    // Run defense-in-depth layers (Bug #15)
    var layers = runDefenseLayers(payload, analysis);

    // Use dynamic detection explanation if payload doesn't match button
    var whyText = atkData.whyDetected;
    if (atkKey === "safe" && analysis.score === 0) {
        whyText = "No malicious patterns were found. This input is a normal alphanumeric string with no special characters, no injection sequences, and no anomalous features.";
    }

    // Build the full result object
    var result = {
        attackType: atkData.label,
        target: currentTarget.charAt(0).toUpperCase() + currentTarget.slice(1) + " Field",
        score: analysis.score,
        blocked: blocked,
        decision: blocked ? "BLOCKED" : "ALLOWED",
        whyDetected: whyText,
        rules: analysis.triggeredRules,
        prevention: atkData.prevention,
        originalPayload: payload,
        sanitizedPayload: sanitize(payload),
        anomalies: analysis.anomalies,
        entropy: analysis.entropy,
        specialChars: analysis.specialChars,
        layers: layers,
        mitre: atkData.mitre,
        timestamp: new Date().toISOString()
    };

    // Forensic log entry (Bug #11)
    addLog(
        atkData.label,
        payload,
        currentTarget.charAt(0).toUpperCase() + currentTarget.slice(1),
        blocked ? "BLOCKED" : "ALLOWED",
        analysis.triggeredRules
    );

    // Save to localStorage and navigate (Bug #7 prevention)
    localStorage.setItem("ids_result", JSON.stringify(result));
    window.location.href = "analysis.html";
}


// ─────────────────────────────────────────
// STATUS MESSAGE HELPER
// Shows a message below action buttons
// ─────────────────────────────────────────
function showStatus(message, type) {
    var el = document.getElementById("status-msg");
    if (!el) return;
    el.textContent = message;
    el.className = "status-msg " + (type === "error" ? "status-error" : "status-ok");
    el.style.display = "block";

    // Auto-hide after 4 seconds
    setTimeout(function () {
        el.style.display = "none";
    }, 4000);
}


// ─────────────────────────────────────────
// RESET
// Clears all inputs, selections, and log
// ─────────────────────────────────────────
function resetAll() {
    document.getElementById("payload-input").value = "";
    document.getElementById("sim-username").value = "";
    document.getElementById("sim-password").value = "";
    document.getElementById("log-box").innerHTML = '<span class="log-empty">No activity yet.</span>';
    sessionStorage.removeItem("ids_activity_log");

    var statusEl = document.getElementById("status-msg");
    if (statusEl) {
        statusEl.style.display = "none";
    }

    document.querySelectorAll(".atk-btn").forEach(function (b) {
        b.classList.remove("selected");
    });

    selectedAttack = null;
    currentTarget = "password";

    document.getElementById("btn-username").classList.remove("active");
    document.getElementById("btn-password").classList.add("active");

    rateLimitTimestamps = [];
}


// ─────────────────────────────────────────
// AUTO-LOGIN ON PAGE LOAD
// If user was already logged in (navigated
// back from analysis.html), skip login form
// and show the dashboard directly.
// ─────────────────────────────────────────
window.addEventListener("DOMContentLoaded", function () {
    if (sessionStorage.getItem("ids_logged_in") === "true") {
        document.getElementById("login-page").style.display = "none";
        document.getElementById("main-page").style.display = "block";

        // Restore default target button state
        document.getElementById("btn-username").classList.remove("active");
        document.getElementById("btn-password").classList.add("active");

        // Restore saved activity log entries
        var savedLogs = JSON.parse(sessionStorage.getItem("ids_activity_log") || "[]");
        if (savedLogs.length > 0) {
            var box = document.getElementById("log-box");
            box.innerHTML = ""; // Clear the "No activity yet" placeholder

            savedLogs.forEach(function (entry) {
                var row = document.createElement("div");
                row.className = "log-row";
                row.innerHTML =
                    '<span class="log-ts">[' + entry.date + " " + entry.time + ']</span> ' +
                    '<span class="' + (entry.decision === "BLOCKED" ? "log-blocked" : "log-allowed") + '">' + entry.decision + '</span> ' +
                    '<span>' + entry.attackType + ' | Target: ' + entry.target + ' | Payload: ' + entry.preview + ' | Rules: ' + entry.ruleIds + '</span>';
                box.appendChild(row);
            });
        }
    }

    // ─────────────────────────────────────────
    // BIDIRECTIONAL SYNC: Payload ↔ Target Password
    // Typing in one updates the other in real-time
    // ─────────────────────────────────────────
    var payloadInput = document.getElementById("payload-input");
    var simPassword = document.getElementById("sim-password");

    if (payloadInput && simPassword) {
        // Payload textarea → Target password field
        payloadInput.addEventListener("input", function () {
            simPassword.value = payloadInput.value;
        });

        // Target password field → Payload textarea
        simPassword.addEventListener("input", function () {
            payloadInput.value = simPassword.value;
        });
    }
});