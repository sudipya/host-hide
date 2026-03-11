const SQLI_RULES = [
  { id: "sqli_union_select", regex: /\bunion\b\s+\bselect\b/i, reason: "UNION SELECT sequence" },
  { id: "sqli_boolean_tautology", regex: /\bor\b\s+1\s*=\s*1\b/i, reason: "Boolean tautology" },
  { id: "sqli_select_from", regex: /\bselect\b\s+.+\bfrom\b/i, reason: "SELECT ... FROM pattern" },
  { id: "sqli_comment", regex: /(--|\/\*|\*\/)/i, reason: "SQL comment marker" },
  { id: "sqli_time_delay", regex: /\b(waitfor\s+delay|sleep\s*\()/i, reason: "Time delay function" },
];

const XSS_RULES = [
  { id: "xss_script_tag", regex: /<\s*script\b/i, reason: "Script tag" },
  { id: "xss_event_handler", regex: /on\w+\s*=/i, reason: "Inline event handler" },
  { id: "xss_js_scheme", regex: /javascript\s*:/i, reason: "javascript: URI scheme" },
  { id: "xss_img_onerror", regex: /<\s*img\b[^>]*onerror\s*=/i, reason: "Image onerror handler" },
  { id: "xss_svg_onload", regex: /<\s*svg\b[^>]*onload\s*=/i, reason: "SVG onload handler" },
];

const RCE_RULES = [
  { id: "rce_shell_chain", regex: /(;|\|\||&&|\|)\s*/i, reason: "Shell chain operator" },
  { id: "rce_substitution", regex: /(\$\([^\)]+\)|`[^`]+`)/i, reason: "Command substitution" },
  { id: "rce_suspicious_binary", regex: /\b(bash|sh|cmd\.exe|powershell|nc|netcat|curl|wget|python\s+-c|perl\s+-e|php\s+-r)\b/i, reason: "Suspicious binary" },
];

const URL_REGEX = /https?:\/\/[^\s'"<>]+/gi;
const SCHEME_REGEX = /\b(file|gopher|dict|ftp|smb|ldap):\/\//gi;

const MAX_ALERTS = 30;
let monitoring = false;
let activeTabId = null;
let lastNotificationAt = 0;
const NOTIFY_COOLDOWN_MS = 5000;

function normalize(text) {
  if (!text) return "";
  let value = text;
  for (let i = 0; i < 2; i += 1) {
    try {
      value = decodeURIComponent(value.replace(/\+/g, "%20"));
    } catch (e) {
      return value;
    }
  }
  return value;
}

function clip(value, limit = 120) {
  if (!value) return "";
  return value.length <= limit ? value : `${value.slice(0, limit - 3)}...`;
}

function findRegexEvidence(rules, text) {
  const evidence = [];
  rules.forEach((rule) => {
    const match = text.match(rule.regex);
    if (match) {
      evidence.push({ rule: rule.id, match: clip(match[0]), reason: rule.reason });
    }
  });
  return evidence;
}

function isInternalHost(host) {
  if (!host) return false;
  const value = host.toLowerCase();
  if (["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata", "metadata.google.internal", "host.docker.internal"].includes(value)) {
    return true;
  }
  if (value.startsWith("10.") || value.startsWith("192.168.") || value.startsWith("169.254.")) return true;
  if (value.startsWith("172.")) {
    const parts = value.split(".");
    const second = parseInt(parts[1], 10);
    return second >= 16 && second <= 31;
  }
  return false;
}

function detectSsrf(text) {
  const evidence = [];
  const urls = text.match(URL_REGEX) || [];
  urls.forEach((candidate) => {
    try {
      const parsed = new URL(candidate);
      if (isInternalHost(parsed.hostname)) {
        evidence.push({
          rule: "ssrf_internal_host",
          match: clip(candidate),
          reason: `Internal host target (${parsed.hostname})`,
        });
      }
    } catch (e) {
      // ignore
    }
  });

  const schemes = text.match(SCHEME_REGEX) || [];
  schemes.forEach((scheme) => {
    evidence.push({
      rule: "ssrf_unusual_scheme",
      match: scheme,
      reason: "Unusual URL scheme",
    });
  });

  return evidence;
}

function buildFinding(name, evidence) {
  const score = Math.min(1, 0.3 * evidence.length);
  const confidence = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";
  return { attack: name, score: score.toFixed(2), confidence, evidence };
}

function analyzeText(payload) {
  const normalized = normalize(payload);
  const findings = [];

  const sqli = findRegexEvidence(SQLI_RULES, normalized);
  if (sqli.length) findings.push(buildFinding("SQLi", sqli));

  const xss = findRegexEvidence(XSS_RULES, normalized);
  if (xss.length) findings.push(buildFinding("XSS", xss));

  const ssrf = detectSsrf(normalized);
  if (ssrf.length) findings.push(buildFinding("SSRF", ssrf));

  const rce = findRegexEvidence(RCE_RULES, normalized);
  if (rce.length) findings.push(buildFinding("RCE", rce));

  return {
    summary: {
      attack_detected: findings.length > 0,
      top_attack: findings.length ? findings[0].attack : "None",
      count: findings.length,
    },
    findings,
  };
}

function decodeRequestBody(details) {
  if (!details || !details.requestBody) return "";
  if (details.requestBody.formData) {
    return JSON.stringify(details.requestBody.formData);
  }
  if (details.requestBody.raw && details.requestBody.raw.length) {
    try {
      const bytes = new Uint8Array(details.requestBody.raw[0].bytes);
      return new TextDecoder().decode(bytes);
    } catch (e) {
      return "";
    }
  }
  return "";
}

function maybeNotify(alert) {
  const now = Date.now();
  if (now - lastNotificationAt < NOTIFY_COOLDOWN_MS) {
    return;
  }
  lastNotificationAt = now;
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon-128.png",
    title: "Anomaly detected",
    message: `${alert.summary.top_attack} indicators found on ${alert.url}`,
  });
}

async function addAlert(alert) {
  const stored = await chrome.storage.local.get("alerts");
  const alerts = stored.alerts || [];
  alerts.unshift(alert);
  if (alerts.length > MAX_ALERTS) {
    alerts.splice(MAX_ALERTS);
  }
  await chrome.storage.local.set({ alerts });
  chrome.runtime.sendMessage({ type: "alert", alert });
  maybeNotify(alert);
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!monitoring) return;
    if (activeTabId !== null && details.tabId !== activeTabId) return;
    const body = decodeRequestBody(details);
    const payload = `${details.method} ${details.url}\n${body}`;
    const result = analyzeText(payload);
    if (!result.summary.attack_detected) return;

    addAlert({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      time: new Date().toISOString(),
      url: details.url,
      method: details.method,
      summary: result.summary,
      findings: result.findings,
    });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return;

  if (message.type === "enableMonitor") {
    monitoring = true;
    activeTabId = message.tabId ?? null;
    chrome.storage.local.set({ alerts: [] });
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "disableMonitor") {
    monitoring = false;
    activeTabId = null;
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "getAlerts") {
    chrome.storage.local.get("alerts").then((data) => {
      sendResponse({ ok: true, alerts: data.alerts || [] });
    });
    return true;
  }

  if (message.type === "clearAlerts") {
    chrome.storage.local.set({ alerts: [] }).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }
});
