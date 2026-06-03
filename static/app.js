// Docker Hardening Checker — frontend logic
(() => {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const kindBtns = $$(".kind-btn");
  const sourceEl = $("#source");
  const fileInput = $("#fileInput");
  const analyzeBtn = $("#analyzeBtn");
  const sampleBtn = $("#sampleBtn");
  const clearBtn = $("#clearBtn");
  const filenameLabel = $("#filenameLabel");
  const autoHint = $("#autoHint");
  const resultsPanel = $("#resultsPanel");
  const findingsEl = $("#findings");
  const summaryEl = $("#summary");
  const emptyMsg = $("#emptyMsg");
  const filters = $$(".sev-filter");

  let currentKind = "dockerfile";
  let currentFilename = "pasted";

  // --- Kind toggle ---
  kindBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      kindBtns.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      currentKind = btn.dataset.kind;
    });
  });

  // --- File handling ---
  fileInput.addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    loadFile(file);
  });

  function loadFile(file) {
    const reader = new FileReader();
    reader.onload = () => {
      sourceEl.value = String(reader.result || "");
      currentFilename = file.name;
      filenameLabel.textContent = file.name;
      // Auto-detect kind from extension if the current kind is "default" (dockerfile)
      const lower = file.name.toLowerCase();
      if (lower.includes("compose") || lower.endsWith(".yml") || lower.endsWith(".yaml")) {
        setKind("compose");
      } else {
        setKind("dockerfile");
      }
      autoHint.textContent = `loaded: ${file.name}`;
    };
    reader.readAsText(file);
  }

  // --- Drag & drop ---
  ["dragenter", "dragover"].forEach((evt) =>
    sourceEl.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      sourceEl.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    sourceEl.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      sourceEl.classList.remove("dragover");
    })
  );
  sourceEl.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) loadFile(file);
  });

  // --- Sample loader ---
  sampleBtn.addEventListener("click", async () => {
    const which = currentKind === "compose" ? "compose-bad.yml" : "Dockerfile.bad";
    try {
      const res = await fetch(`/api/sample?which=${encodeURIComponent(which)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      sourceEl.value = data.content;
      currentFilename = which;
      filenameLabel.textContent = which;
      autoHint.textContent = `loaded: ${which}`;
    } catch (e) {
      toast("Failed to load sample: " + e.message, true);
    }
  });

  // --- Clear ---
  clearBtn.addEventListener("click", () => {
    sourceEl.value = "";
    currentFilename = "pasted";
    filenameLabel.textContent = "unsaved";
    autoHint.textContent = "auto-detected from file name";
    resultsPanel.hidden = true;
  });

  // --- Analyze ---
  analyzeBtn.addEventListener("click", analyze);
  sourceEl.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyze();
    }
  });

  async function analyze() {
    const content = sourceEl.value;
    if (!content.trim()) {
      toast("Nothing to analyze — paste a Dockerfile or load a file first.", true);
      return;
    }
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing…";
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: currentKind, content, filename: currentFilename }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      renderResults(data);
    } catch (e) {
      toast("Analyze failed: " + e.message, true);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "Analyze";
    }
  }

  function renderResults(data) {
    const findings = data.findings || [];
    const summary = data.summary || {};
    summaryEl.innerHTML = "";
    const order = ["critical", "high", "medium", "low", "info"];
    let totalShown = 0;
    order.forEach((sev) => {
      const n = summary[sev] || 0;
      if (!n) return;
      const pill = document.createElement("span");
      pill.className = `pill ${sev}`;
      pill.textContent = `${n} ${sev}`;
      summaryEl.appendChild(pill);
      totalShown += n;
    });
    if (totalShown === 0) {
      const pill = document.createElement("span");
      pill.className = "pill low";
      pill.textContent = "clean";
      summaryEl.appendChild(pill);
    }

    findingsEl.innerHTML = "";
    findings.forEach((f) => {
      const li = document.createElement("li");
      li.className = `finding sev-${f.severity}`;
      li.dataset.severity = f.severity;
      li.innerHTML = `
        <div class="finding-head">
          <h3>${escapeHtml(f.title)}<span class="badge sev-${f.severity}">${f.severity}</span></h3>
          <div>
            <span class="rule-id">${escapeHtml(f.rule_id)}</span>
            ${f.line ? `<span class="line">line ${f.line}</span>` : ""}
          </div>
        </div>
        <p>${escapeHtml(f.description)}</p>
        ${f.snippet ? `<pre class="snippet mono">${escapeHtml(f.snippet)}</pre>` : ""}
        <div class="remediation">${escapeHtml(f.remediation)}</div>
      `;
      findingsEl.appendChild(li);
    });

    resultsPanel.hidden = false;
    applyFilters();
    if (data.warning) toast(data.warning, true);
  }

  function applyFilters() {
    const active = new Set(filters.filter((f) => f.checked).map((f) => f.value));
    let visible = 0;
    $$(".finding").forEach((el) => {
      if (active.has(el.dataset.severity)) {
        el.style.display = "";
        visible++;
      } else {
        el.style.display = "none";
      }
    });
    emptyMsg.hidden = visible !== 0;
  }

  filters.forEach((f) => f.addEventListener("change", applyFilters));

  // --- Utilities ---
  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function setKind(kind) {
    currentKind = kind;
    kindBtns.forEach((b) => {
      const on = b.dataset.kind === kind;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", String(on));
    });
  }

  let toastTimer = null;
  function toast(msg, isError = false) {
    const existing = document.querySelector(".toast");
    if (existing) existing.remove();
    const t = document.createElement("div");
    t.className = "toast" + (isError ? " error" : "");
    t.textContent = msg;
    document.body.appendChild(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), 5000);
  }
})();
