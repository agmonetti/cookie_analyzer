let savedCookies = [];
let currentTab = null;

/**
 * Database of known malicious or tracking cookies
 */
const knownCookies = {
    malicious: [
        '_ga', '_gid', '_gat', '_gtag', '_fbp', '_fbc', 'fr', 'doubleclick',
        '_hjid', '_hjFirstSeen', '_hjIncludedInSessionSample', 'hotjar',
        'amplitude', 'mixpanel', 'segment', 'intercom', 'drift',
        '__utma', '__utmb', '__utmc', '__utmz', '__utmt',
        'yandex_metrica', 'ya_metrica', '_ym_', '_yasc',
        'optimizely', 'vwo_uuid', 'ab_test', 'split_test'
    ],
    tracking: [
        '_dc_gtm', '_gcl_', '_gac_', 'ads', 'adnxs', 'doubleclick',
        'facebook', 'linkedin', 'twitter', 'pinterest'
    ],
    fingerprinting: [
        'canvas_fp', 'webgl_fp', 'audio_fp', 'font_fp', 'screen_fp'
    ]
};

/**
 * Known tracking company domain patterns
 */
const trackingDomains = [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'facebook.com', 'connect.facebook.net', 'hotjar.com',
    'mixpanel.com', 'segment.com', 'amplitude.com',
    'yandex.ru', 'mc.yandex.ru', 'optimizely.com'
];

/**
 * Detects fingerprinting cookies based on advanced patterns
 */
function isFingerprinting(name, value, cookie) {
    const fingerprintPatterns = [
        /canvas|webgl|audio|font|screen|timezone|language|plugins/i,
        /fp_|fingerprint|device_id|browser_id/i,
        /^[a-f0-9]{16,64}$/i // Device characteristics hash
    ];
    
    return fingerprintPatterns.some(pattern => 
        pattern.test(name) || pattern.test(value)
    );
}

/**
 * Detects tracking cookies based on known domains and names
 */
function isTracking(name, value, cookie) {
    const trackingPatterns = [
        /^_ga|_gid|_gat|_gtag|_utm|__utm/i,
        /facebook|fb_|_fbp|_fbc/i,
        /doubleclick|googlesyndication/i,
        /hotjar|mixpanel|segment|amplitude/i
    ];
    
    // Check if cookie belongs to known tracking domain
    const trackingDomain = trackingDomains.some(domain => 
        cookie.domain.includes(domain)
    );
    
    // Check patterns in name
    const trackingPattern = trackingPatterns.some(pattern => 
        pattern.test(name) || pattern.test(value)
    );
    
    return trackingDomain || trackingPattern || knownCookies.malicious.includes(name);
}

/**
 * Detects third-party (cross-site) cookies
 */
function isThirdParty(cookie, currentUrl) {
    if (!currentUrl || !cookie.domain) return false;
    
    try {
        const currentDomain = new URL(currentUrl).hostname;
        const cleanCurrentDomain = currentDomain.replace(/^www\./, '');
        const cookieDomain = cookie.domain.replace(/^\./, '').replace(/^www\./, '');
        
        return !cookieDomain.includes(cleanCurrentDomain) && !cleanCurrentDomain.includes(cookieDomain);
    } catch (e) {
        return false;
    }
}

/**
 * Analyzes value entropy (detects random/encrypted values)
 */
function hasHighEntropy(value) {
    if (value.length < 10) return false;
    
    const charCounts = {};
    for (let char of value) {
        charCounts[char] = (charCounts[char] || 0) + 1;
    }
    
    let entropy = 0;
    const len = value.length;
    for (let count of Object.values(charCounts)) {
        const probability = count / len;
        entropy -= probability * Math.log2(probability);
    }
    
    return entropy > 4; // High entropy indicates random/encrypted value
}

/**
 * Calculates cookie risk level (0-100)
 */
function calculateRisk(name, value, cookie) {
    let risk = 0;
    
    // Critical security patterns - MOVED TO BEGINNING
    const patterns = /token|auth|session|jwt|access|refresh|csrf|secret|key|api|bearer|sid|uid|login|password|hash/i;
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    const hexRegex = /^[a-f0-9]{32,}$/i;
    const base64Regex = /^[A-Za-z0-9+/=]{40,}$/;
    const isHttps = currentTab?.url?.startsWith('https:');
    
    // CRITICAL SECURITY RISKS (higher score)
    if (patterns.test(name)) risk += 35; // Authentication-related name
    if (patterns.test(value)) risk += 30; // Authentication-related value
    if (jwtRegex.test(value)) risk += 40; // JWT token detected
    if (hexRegex.test(value)) risk += 25; // Long hexadecimal hash
    if (base64Regex.test(value)) risk += 25; // Long base64 string
    
    // Insecure configuration for sensitive cookies
    if (patterns.test(name) || patterns.test(value)) {
        if (!cookie.httpOnly) risk += 25; // Sensitive cookie accessible from JavaScript
        if (!cookie.secure && (isHttps || currentTab?.url?.includes('localhost'))) risk += 20; // Sensitive cookie without Secure
        if (!cookie.sameSite || cookie.sameSite === 'none') risk += 20; // Sensitive cookie without SameSite
    } else {
        // For non-sensitive cookies, lower penalty
        if (!cookie.httpOnly) risk += 10;
        if (!cookie.secure && isHttps) risk += 8;
        if (!cookie.sameSite || cookie.sameSite === 'none') risk += 8;
    }
    
    // Known tracking cookies
    if (knownCookies.malicious.includes(name)) risk += 40;
    if (isTracking(name, value, cookie)) risk += 35;
    if (isFingerprinting(name, value, cookie)) risk += 45;
    if (isThirdParty(cookie, currentTab?.url)) risk += 25;
    
    // Additional suspicious characteristics
    if (value.length > 100) risk += 15;
    if (hasHighEntropy(value)) risk += 20;
    
    // Extreme malicious patterns
    const maliciousPatterns = /malware|virus|exploit|xss|injection|backdoor/i;
    if (maliciousPatterns.test(name) || maliciousPatterns.test(value)) risk += 80;
    
    return Math.min(risk, 100);
}

/**
 * Returns array with reasons why a cookie is suspicious/insecure
 */
function suspiciousReasons(name, value, cookie) {
    const reasons = [];
    
    // Critical security patterns
    const patterns = /token|auth|session|jwt|access|refresh|csrf|secret|key|api|bearer|sid|uid|login|password|hash/i;
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    const hexRegex = /^[a-f0-9]{32,}$/i;
    const base64Regex = /^[A-Za-z0-9+/=]{40,}$/;
    const isHttps = currentTab?.url?.startsWith('https:');
    const isLocalhost = currentTab?.url?.includes('localhost') || currentTab?.url?.includes('127.0.0.1');
    
    // Detect if it's a sensitive cookie
    const isSensitiveCookie = patterns.test(name) || patterns.test(value);
    
    // Categorization by type
    if (knownCookies.malicious.includes(name)) {
        reasons.push("Known tracking cookie");
    }
    
    if (isTracking(name, value, cookie)) {
        reasons.push("Tracking/analytics cookie");
    }
    
    if (isFingerprinting(name, value, cookie)) {
        reasons.push("Possible device fingerprinting");
    }
    
    if (isThirdParty(cookie, currentTab?.url)) {
        reasons.push("Third-party (cross-site) cookie");
    }
    
    if (hasHighEntropy(value)) {
        reasons.push("High entropy value (possibly encrypted)");
    }
    
    // Enhanced security analysis
    if (value.length > 100) reasons.push("Extremely long value");
    if (patterns.test(name)) reasons.push("⚠️ CRITICAL: Authentication/session related name");
    if (patterns.test(value)) reasons.push("⚠️ CRITICAL: Authentication related value");
    if (jwtRegex.test(value)) reasons.push("🔴 CRITICAL: JWT token detected");
    if (hexRegex.test(value)) reasons.push("Long hexadecimal hash");
    if (base64Regex.test(value)) reasons.push("Long base64 string");
    
    // Security configuration - stricter for sensitive cookies
    if (isSensitiveCookie) {
        if (!cookie.httpOnly) reasons.push("🔴 CRITICAL: Sensitive cookie accessible from JavaScript (XSS risk)");
        if (!cookie.secure && (isHttps || isLocalhost)) reasons.push("🔴 CRITICAL: Sensitive cookie without Secure flag");
        if (!cookie.sameSite || cookie.sameSite === 'none') reasons.push("🔴 CRITICAL: Sensitive cookie without SameSite protection (CSRF risk)");
    } else {
        if (!cookie.httpOnly) reasons.push("Without HttpOnly flag (accessible from JavaScript)");
        if (!cookie.secure && isHttps) reasons.push("Without Secure flag on HTTPS site");
        if (!cookie.sameSite || cookie.sameSite === 'none') reasons.push("Without SameSite protection");
    }
    
    const risk = calculateRisk(name, value, cookie);
    return { reasons, risk };
}

/**
 * Determines if a cookie is suspicious/insecure
 */
function isSuspicious(name, value, cookie) {
    const { risk } = suspiciousReasons(name, value, cookie);
    return risk >= 30;
}

/**
 * Gets color based on risk level
 */
function getRiskColor(risk) {
    if (risk >= 70) return 'critical';
    if (risk >= 50) return 'high';
    if (risk >= 30) return 'medium';
    return 'low';
}

// Main function to load cookies
async function loadCookies() {
  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;
    
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('moz-extension://')) {
      document.getElementById("cookie-list").innerHTML = 
        "<div class='no-cookies'>Cannot analyze cookies on browser internal pages.</div>";
      return;
    }

    // Get cookies from current site
    const url = new URL(tab.url);
    const cookies = await chrome.cookies.getAll({ domain: url.hostname });
    
    savedCookies = cookies;
    showCookies(cookies);
  } catch (error) {
    console.error('Error loading cookies:', error);
    document.getElementById("cookie-list").innerHTML = 
      "<div class='no-cookies'>Error loading cookies: " + error.message + "</div>";
  }
}

function showCookies(cookies) {
  const list = document.getElementById("cookie-list");
  list.innerHTML = "";

  // Sort cookies by risk level (highest risk first)
  const sortedCookies = cookies.sort((a, b) => {
    const riskA = calculateRisk(a.name, a.value, a);
    const riskB = calculateRisk(b.name, b.value, b);
    return riskB - riskA;
  });

  sortedCookies.forEach(c => {
    const { reasons, risk } = suspiciousReasons(c.name, c.value, c);
    const suspicious = risk >= 30;
    const riskLevel = getRiskColor(risk);
    
    const div = document.createElement("div");
    // CORRECTION: If risk is < 30, use 'safe', otherwise use risk level
    div.className = `cookie ${risk < 30 ? 'safe' : riskLevel}`;

    let expires = c.expirationDate
      ? new Date(c.expirationDate * 1000).toLocaleString()
      : "Session";

    // Truncate value if too long
    const displayValue = c.value.length > 50 
      ? c.value.substring(0, 50) + '...' 
      : c.value;

    div.innerHTML = `
      <div class="cookie-header">
        <strong>${c.name}</strong>
        <span class="risk-badge risk-${riskLevel}">Risk: ${risk}%</span>
      </div>
      <div class="cookie-details">
        <strong>Value:</strong> <code title="${c.value}">${displayValue}</code><br>
        <strong>Domain:</strong> ${c.domain}<br>
        <strong>Security:</strong> Secure: ${c.secure ? '✓' : '✗'}, HttpOnly: ${c.httpOnly ? '✓' : '✗'}, SameSite: ${c.sameSite || 'None'}<br>
        <strong>Expires:</strong> ${expires}
      </div>
    `;

    // Only show reasons and delete button if suspicious (risk >= 30)
    if (suspicious && reasons.length > 0) {
      const reasonsDiv = document.createElement("div");
      reasonsDiv.className = "suspicious-reasons";
      reasonsDiv.innerHTML = "<strong>⚠️ Alert reasons:</strong>";
      
      const ul = document.createElement("ul");
      reasons.forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        ul.appendChild(li);
      });
      reasonsDiv.appendChild(ul);
      div.appendChild(reasonsDiv);

      const btn = document.createElement("button");
      btn.textContent = "🗑️ Remove";
      btn.className = "btn-remove";
      btn.onclick = () => removeCookie(c);
      div.appendChild(btn);
    }

    list.appendChild(div);
  });

  if (cookies.length === 0) {
    list.innerHTML = "<div class='no-cookies'>No cookies available.</div>";
  }

  // Show risk summary
  showRiskSummary(cookies);
}

/**
 * Shows summary of found risks
 */
function showRiskSummary(cookies) {
  const summary = document.getElementById("risk-summary") || document.createElement("div");
  summary.id = "risk-summary";
  summary.className = "risk-summary";

  const stats = {
    total: cookies.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    safe: 0
  };

  cookies.forEach(c => {
    const risk = calculateRisk(c.name, c.value, c);
    
    // CORRECTION: Cookies with risk < 30 are considered safe
    if (risk < 30) {
      stats.safe++;
    } else if (risk >= 70) {
      stats.critical++;
    } else if (risk >= 50) {
      stats.high++;
    } else if (risk >= 30) {
      stats.medium++;
    }
  });

  summary.innerHTML = `
    <h3>📊 Analysis Summary</h3>
    <div class="stats-grid">
      <div class="stat critical">Critical: ${stats.critical}</div>
      <div class="stat high">High: ${stats.high}</div>
      <div class="stat medium">Medium: ${stats.medium}</div>
      <div class="stat safe">Safe: ${stats.safe}</div>
    </div>
  `;

  if (!document.getElementById("risk-summary")) {
    document.getElementById("cookie-list").parentNode.insertBefore(summary, document.getElementById("cookie-list"));
  }
}

// Function to remove a specific cookie
async function removeCookie(cookie) {
  try {
    await chrome.cookies.remove({
      url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
      name: cookie.name
    });
    
    // Reload list
    loadCookies();
  } catch (error) {
    console.error('Error removing cookie:', error);
    alert('Error removing cookie: ' + error.message);
  }
}

// Function to remove suspicious cookies
async function removeSuspicious() {
  if (!savedCookies || savedCookies.length === 0) {
    alert('No cookies to analyze');
    return;
  }

  const suspicious = savedCookies.filter(c => isSuspicious(c.name, c.value, c));
  
  if (suspicious.length === 0) {
    alert('No suspicious cookies found');
    return;
  }

  if (confirm(`Remove ${suspicious.length} suspicious cookies?`)) {
    try {
      for (const cookie of suspicious) {
        await chrome.cookies.remove({
          url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
          name: cookie.name
        });
      }
      loadCookies();
    } catch (error) {
      console.error('Error removing cookies:', error);
      alert('Error removing cookies: ' + error.message);
    }
  }
}

// Function to remove all cookies
async function removeAll() {
  if (!currentTab) {
    alert('Could not get current tab information');
    return;
  }

  try {
    const url = new URL(currentTab.url);
    const cookies = await chrome.cookies.getAll({ domain: url.hostname });
    
    if (cookies.length === 0) {
      alert('No cookies to remove');
      return;
    }

    if (confirm(`Remove ALL ${cookies.length} cookies from site ${url.hostname}?`)) {
      for (const cookie of cookies) {
        await chrome.cookies.remove({
          url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
          name: cookie.name
        });
      }
      loadCookies();
    }
  } catch (error) {
    console.error('Error removing all cookies:', error);
    alert('Error removing cookies: ' + error.message);
  }
}

// Event listeners for buttons
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('remove-suspicious').addEventListener('click', removeSuspicious);
  document.getElementById('remove-all').addEventListener('click', removeAll);
  
  // Load cookies on start
  loadCookies();
});
