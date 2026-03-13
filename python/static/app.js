const form = document.getElementById("quiz-form");
const pptInput = document.getElementById("ppt-file");
const fileHint = document.getElementById("file-hint");
const difficultyInput = document.getElementById("difficulty");
const difficultyGroup = document.getElementById("difficulty-group");
const countInput = document.getElementById("question-count");
const apiUrlInput = document.getElementById("api-url");
const statusEl = document.getElementById("status");
const resultTitle = document.getElementById("result-title");
const resultMeta = document.getElementById("result-meta");
const questionsEl = document.getElementById("questions");
const copyButton = document.getElementById("copy-json");
const resetButton = document.getElementById("reset");

let lastResponse = null;

function setStatus(type, message) {
  statusEl.classList.remove("good", "bad", "neutral");
  statusEl.classList.add(type);
  statusEl.textContent = message;
}

function getDefaultApiUrl() {
  if (window.location.protocol === "file:") {
    return "http://localhost:8000/api/quiz";
  }
  return `${window.location.origin}/api/quiz`;
}

function getApiUrl() {
  const raw = apiUrlInput.value.trim();
  return raw || getDefaultApiUrl();
}

function renderEmpty() {
  questionsEl.innerHTML = "<div class=\"empty\">Your generated quiz will appear here.</div>";
  copyButton.disabled = true;
}

function renderQuiz(data) {
  const questions =
    data?.questions ||
    data?.quiz?.questions ||
    data?.items ||
    [];

  const title = data?.title || data?.quiz?.title || "Generated Quiz";
  const difficulty = data?.difficulty || difficultyInput.value;
  const source = data?.source ? `• ${data.source}` : "";

  resultTitle.textContent = title;
  resultMeta.textContent = `${questions.length} questions • ${difficulty}${source ? ` ${source}` : ""}`;

  questionsEl.innerHTML = "";

  if (!questions.length) {
    renderEmpty();
    return;
  }

  questions.forEach((item, index) => {
    const card = document.createElement("div");
    card.className = "question-card";

    const qText = item.question || item.prompt || `Question ${index + 1}`;
    const options = Array.isArray(item.options) ? item.options : [];
    const answer = item.answer || item.correct || "";
    const explanation = item.explanation || item.reasoning || "";

    let optionsHtml = "";
    if (options.length) {
      optionsHtml = `<ul>${options.map((opt) => `<li>${opt}</li>`).join("")}</ul>`;
    }

    const answerHtml = answer
      ? `<div class=\"answer\">Answer: ${answer}</div>`
      : "";
    const explanationHtml = explanation ? `<div class=\"muted\">${explanation}</div>` : "";

    card.innerHTML = `
      <h4>${index + 1}. ${qText}</h4>
      ${optionsHtml}
      ${answerHtml}
      ${explanationHtml}
    `;

    questionsEl.appendChild(card);
  });

  copyButton.disabled = false;
}

async function handleSubmit(event) {
  event.preventDefault();

  const apiUrl = getApiUrl();
  const file = pptInput.files[0];
  const count = countInput.value;
  const difficulty = difficultyInput.value;

  if (!file && apiUrlInput.value.trim()) {
    setStatus("bad", "Please attach a PPT/PPTX file for your API call.");
    return;
  }

  const formData = new FormData();
  if (file) {
    formData.append("ppt", file);
  }
  formData.append("difficulty", difficulty);
  formData.append("count", count);

  setStatus("neutral", "Uploading deck and generating quiz...");
  resultTitle.textContent = "Generating...";
  resultMeta.textContent = "Stand by while we build your quiz.";
  questionsEl.innerHTML = "";

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || "Quiz API error");
    }

    const data = await response.json();
    lastResponse = data;
    renderQuiz(data);
    setStatus("good", "Quiz ready.");
  } catch (error) {
    console.error(error);
    renderEmpty();
    setStatus("bad", "Could not generate quiz. Check the API URL or backend.");
  }
}

function handleDifficultyClick(event) {
  const button = event.target.closest(".pill");
  if (!button) {
    return;
  }
  const value = button.dataset.value;
  difficultyInput.value = value;
  Array.from(difficultyGroup.children).forEach((pill) =>
    pill.classList.toggle("active", pill === button)
  );
}

function handleReset() {
  form.reset();
  difficultyInput.value = "easy";
  Array.from(difficultyGroup.children).forEach((pill) =>
    pill.classList.toggle("active", pill.dataset.value === "easy")
  );
  lastResponse = null;
  fileHint.textContent = "PPTX recommended (PPT may not parse).";
  resultTitle.textContent = "No quiz yet";
  resultMeta.textContent = "Upload a PPT to see questions here.";
  renderEmpty();
  setStatus("neutral", "Ready to generate.");
}

async function copyJson() {
  if (!lastResponse) {
    return;
  }
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResponse, null, 2));
    setStatus("good", "Quiz JSON copied to clipboard.");
  } catch (error) {
    setStatus("bad", "Copy failed. Try again.");
  }
}

pptInput.addEventListener("change", () => {
  const file = pptInput.files[0];
  if (file) {
    fileHint.textContent = `${file.name} • ${(file.size / (1024 * 1024)).toFixed(1)} MB`;
  } else {
    fileHint.textContent = "PPTX recommended (PPT may not parse).";
  }
});

form.addEventListener("submit", handleSubmit);
difficultyGroup.addEventListener("click", handleDifficultyClick);
resetButton.addEventListener("click", handleReset);
copyButton.addEventListener("click", copyJson);

renderEmpty();
