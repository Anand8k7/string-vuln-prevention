/* String Vulnerability Lab - frontend (plain JavaScript, no framework). */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const SAMPLES = { scan: {}, runtime: {}, input: {} };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function cweLink(cwe) {
  const m = /CWE-(\d+)/.exec(cwe || "");
  if (!m) return cwe ? `<span class="cwe">${esc(cwe)}</span>` : "";
  return `<a class="cwe" href="https://cwe.mitre.org/data/definitions/${m[1]}.html" target="_blank" rel="noopener noreferrer">${esc(m[0])}</a>`;
}

async function api(path, data) {
  const opts = data === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data),
  };
  const res = await fetch(path, opts);
  let json;
  try { json = await res.json(); } catch { json = { error: `Server returned ${res.status}` }; }
  if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
  return json;
}

function loading(el, text) {
  el.innerHTML = `<div class="loading"><div class="spinner"></div>${esc(text)}</div>`;
}
function showError(el, err) {
  el.innerHTML = `<div class="alert error">${esc(err.message || err)}</div>`;
}
async function withButton(btn, fn) {
  btn.disabled = true;
  try { await fn(); } finally { btn.disabled = false; }
}

/* Render code with line numbers. marks: {line: {cls, tag}} */
function codeView(code, marks = {}, idPrefix = "") {
  const lines = code.replace(/\n$/, "").split("\n");
  return lines.map((l, i) => {
    const n = i + 1, m = marks[n];
    const cls = m ? ` hl-${m.cls}` : "";
    const tag = m && m.tag ? `<span class="tag">← ${esc(m.tag)}</span>` : "";
    const id = idPrefix ? ` id="${idPrefix}${n}"` : "";
    return `<div class="code-row${cls}"${id}><span class="ln">${n}</span><span class="src">${esc(l) || " "}${tag}</span></div>`;
  }).join("");
}

function jumpTo(id) {
  const row = document.getElementById(id);
  if (!row) return;
  row.scrollIntoView({ block: "center", behavior: "smooth" });
  row.classList.remove("flash"); void row.offsetWidth; row.classList.add("flash");
}

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

function fillSelect(sel, names) {
  sel.innerHTML = names.map(n => `<option>${esc(n)}</option>`).join("");
}

function bytes(n) { return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`; }
function sizeCounter(area, label) {
  const upd = () => { label.textContent = bytes(new Blob([area.value]).size); };
  area.addEventListener("input", upd); upd();
  return upd;
}

/* ------------------------------------------------------------------ tabs */
document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === `tab-${t.dataset.tab}`));
  if (t.dataset.tab === "examples") initExamples();
}));

/* Tab key inserts 4 spaces in code areas */
document.querySelectorAll(".code-input").forEach(a => a.addEventListener("keydown", e => {
  if (e.key !== "Tab") return;
  e.preventDefault();
  const s = a.selectionStart;
  a.setRangeText("    ", s, a.selectionEnd, "end");
  a.dispatchEvent(new Event("input"));
}));

/* ============================================================ 1 Scanner */
const scanCode = $("#scan-code");
const updScanSize = sizeCounter(scanCode, $("#scan-size"));

$("#scan-load").addEventListener("click", () => {
  scanCode.value = SAMPLES.scan[$("#scan-sample").value] || "";
  updScanSize();
});

$("#scan-run").addEventListener("click", e => withButton(e.target, async () => {
  const out = $("#scan-result");
  loading(out, "Scanning with rules and cppcheck…");
  try {
    const code = scanCode.value;
    const r = await api("/api/scan", { code, lang: $("#scan-lang").value });
    renderScan(out, code, r);
  } catch (err) { showError(out, err); }
}));

function renderScan(out, code, r) {
  const s = r.summary;
  const color = s.score >= 90 ? "var(--good)" : s.score >= 50 ? "var(--medium)" : "var(--high)";
  const chips = ["critical", "high", "medium", "low"].map(k =>
    `<span class="pill sev-${k}">${s.counts[k] || 0} ${k}</span>`).join("");
  const cpp = r.cppcheck.available ? `cppcheck: ${r.cppcheck.count} finding(s)` : "cppcheck not installed";

  const marks = {};
  for (const f of r.findings) {
    const cur = marks[f.line];
    if (!cur || SEV_ORDER[f.severity] > SEV_ORDER[cur.cls]) marks[f.line] = { cls: f.severity, tag: f.cwe };
  }
  const items = r.findings.map(f => `
    <div class="finding sev-${f.severity}">
      <div class="finding-head">
        <span class="pill sev-${f.severity}">${esc(f.severity)}</span>
        <button class="line-link" data-jump="scan-l${f.line}">line ${f.line}</button>
        ${cweLink(f.cwe)}
        <span class="finding-title">${esc(f.title)}</span>
        <span class="source-tag">${f.source === "cppcheck" ? "cppcheck" : "rule scanner"}</span>
      </div>
      ${f.detail ? `<p class="detail">${esc(f.detail)}</p>` : ""}
      <p>${esc(f.explain)}</p>
      <div class="fix"><b>Safe replacement:</b> ${esc(f.fix)}</div>
      ${(f.cppcheck || []).map(c => `<div class="confirm">Also reported by cppcheck: <code>${esc(c.id)}</code> ${esc(c.message)}</div>`).join("")}
    </div>`).join("");

  out.innerHTML = `
    <div class="result-block">
      <div class="summary">
        <div class="score-ring" style="--p:${s.score};--c:${color}"><div><b>${s.score}</b><small>/ 100</small></div></div>
        <div>
          <div class="grade">Grade <b>${esc(s.grade)}</b> · ${s.total} finding(s)</div>
          <div class="chips">${chips}</div>
          <div class="hint" style="margin-top:6px">Rule scanner: ${r.rule_count} · ${cpp}. Score = 100 − (25 per critical, 15 high, 8 medium, 3 low).</div>
        </div>
      </div>
      <h3>Code</h3>
      <div class="code-view">${codeView(code, marks, "scan-l")}</div>
      <h3>Findings</h3>
      ${r.findings.length ? `<div class="findings">${items}</div>` : `<div class="empty">No string vulnerabilities found by the rules or cppcheck.</div>`}
    </div>`;
}

/* ============================================================ 2 Runtime */
const rtCode = $("#rt-code");
const updRtSize = sizeCounter(rtCode, $("#rt-size"));

$("#rt-load").addEventListener("click", () => {
  const s = SAMPLES.runtime[$("#rt-sample").value];
  if (!s) return;
  rtCode.value = s.code; $("#rt-args").value = s.args; $("#rt-stdin").value = s.stdin;
  updRtSize();
});

$("#rt-run").addEventListener("click", e => withButton(e.target, async () => {
  const out = $("#rt-result");
  loading(out, "Compiling with ASan + UBSan and running…");
  try {
    const code = rtCode.value;
    const r = await api("/api/runtime", {
      code, lang: $("#rt-lang").value, args: $("#rt-args").value, stdin: $("#rt-stdin").value,
    });
    renderRuntime(out, code, r);
  } catch (err) { showError(out, err); }
}));

function explainCards(findings) {
  if (!findings || !findings.length) return "";
  return `<div class="explain-list">${findings.map(f => {
    const cls = f.tool === "LeakSanitizer" ? " leak" : f.tool === "UBSan" ? " ub" : "";
    const facts = [];
    if (f.location) facts.push(`line <b>${f.location.line}</b>${f.location.function ? ` in <b>${esc(f.location.function)}</b>` : ""}`);
    if (f.variable) facts.push(`variable <b>${esc(f.variable)}</b>`);
    if (f.variable_size !== undefined) facts.push(`buffer size <b>${f.variable_size} B</b>`);
    if (f.bytes !== undefined) facts.push(`${esc(f.access || "access")} of <b>${f.bytes} B</b>`);
    if (f.allocated_at) facts.push(`allocated at line <b>${f.allocated_at.line}</b>`);
    if (f.freed_at) facts.push(`freed at line <b>${f.freed_at.line}</b>`);
    return `<div class="explain${cls}">
      <div class="explain-head"><span>${esc(f.title)}</span>${cweLink(f.cwe)}<span class="source-tag">${esc(f.tool)}</span></div>
      <p>${esc(f.plain)}</p>
      ${facts.length ? `<div class="facts">${facts.join("<span>·</span>")}</div>` : ""}
    </div>`;
  }).join("")}</div>`;
}

function renderRuntime(out, code, r) {
  const v = r.verdict;
  const marks = {};
  for (const d of r.compile.diagnostics || []) {
    if (d.kind === "note") continue;
    marks[d.line] = { cls: d.kind === "error" ? "high" : "medium", tag: `${d.kind}: ${d.message}` };
  }
  for (const f of r.findings || []) {
    if (f.allocated_at) marks[f.allocated_at.line] = { cls: "low", tag: "allocated here" };
    if (f.freed_at) marks[f.freed_at.line] = { cls: "low", tag: "freed here" };
    if (f.declared_line) marks[f.declared_line] = { cls: "low", tag: `'${f.variable}' declared here` };
  }
  for (const f of r.findings || []) {
    if (f.location) marks[f.location.line] = { cls: f.tool === "LeakSanitizer" ? "medium" : "high", tag: f.title };
  }
  const run = r.run;
  const runInfo = run ? `exit code ${run.rc}${run.signal ? ` (${run.signal})` : ""} · ${run.duration}s${run.truncated ? " · output truncated to 64 KB" : ""}` : "";
  const warnings = (r.compile.diagnostics || []).filter(d => d.kind === "warning");

  out.innerHTML = `
    <div class="verdict lvl-${v.level}"><span class="badge lvl-${v.level}">${esc(v.label)}</span><p>${esc(v.text)}</p></div>
    ${explainCards(r.findings)}
    ${warnings.length ? `<div class="alert info">Compiler warnings: ${warnings.map(w => `line ${w.line}: ${esc(w.message)}`).join(" · ")}</div>` : ""}
    <h3>Code</h3>
    <div class="code-view">${codeView(code, marks)}</div>
    ${run ? `<h3>Program output <span class="hint">(${esc(runInfo)})</span></h3>
      <pre class="output">${esc(stripSanitizer(run.output)) || "(no output)"}</pre>
      <details><summary>Raw output with the full sanitizer report</summary><pre class="output">${esc(run.output) || "(empty)"}</pre></details>` : ""}
    <details ${r.compile.ok ? "" : "open"}><summary>Compiler output</summary><pre class="output">${esc(r.compile.output) || "(no messages)"}</pre></details>`;
}

/* program output without the long sanitizer report */
function stripSanitizer(text) {
  const i = text.search(/^=+\n==\d+==ERROR|^==\d+==ERROR|^\S+:\d+:\d+: runtime error/m);
  return (i === -1 ? text : text.slice(0, i) + "[sanitizer report - see raw output below]").trimEnd();
}

/* ======================================================= 3 Input Tester */
const IN_FIELDS = ["name", "role", "age", "message"];

$("#in-load").addEventListener("click", () => {
  const s = SAMPLES.input[$("#in-sample").value];
  if (s) IN_FIELDS.forEach(k => { $(`#in-${k}`).value = s[k]; });
});

$("#in-run").addEventListener("click", e => withButton(e.target, async () => {
  const out = $("#in-result");
  loading(out, "Running Q1 and Q2: vulnerable, vulnerable + ASan, secure, secure + ASan…");
  try {
    const data = Object.fromEntries(IN_FIELDS.map(k => [k, $(`#in-${k}`).value]));
    const r = await api("/api/input-test", data);
    out.innerHTML = `
      <div class="q-section">
        <div class="q-head"><h3>Q1 – Buffer overflow (strcpy / strcat)</h3>
          <span class="sent">argv: ${r.q1.args.map(a => `<code>${esc(a)}</code>`).join(" ")}</span></div>
        ${runGrid(r.q1.runs)}
      </div>
      <div class="q-section">
        <div class="q-head"><h3>Q2 – Input validation &amp; format string (scanf / sprintf / printf)</h3>
          <span class="sent">stdin: <code>${esc(r.q2.stdin.replace(/\n/g, "\\n"))}</code></span></div>
        ${runGrid(r.q2.runs)}
      </div>`;
  } catch (err) { showError(out, err); }
}));

function runGrid(runs) {
  return `<div class="run-grid">${runs.map(x => {
    const b = x.badge, r = x.run;
    const expl = x.findings && x.findings.length ? `<p class="why">${esc(x.findings[0].plain)}</p>` : "";
    return `<div class="run-card ${x.secure ? "secure" : "vulnerable"}">
      <h4>${esc(x.label)}</h4>
      <div class="bin">${esc(x.binary)}</div>
      <div><span class="badge lvl-${b.level}">${esc(b.label)}</span></div>
      ${x.findings && x.findings.length ? expl : `<p class="why">${esc(b.text)}</p>`}
      <div class="rc">exit code ${r.rc}${r.signal ? ` (${r.signal})` : ""} · ${r.duration}s</div>
      <pre class="output">${esc(stripSanitizer(r.output)) || "(no output)"}</pre>
      ${x.findings && x.findings.length ? `<details><summary>Raw ASan output</summary><pre class="output">${esc(r.output)}</pre></details>` : ""}
    </div>`;
  }).join("")}</div>`;
}

/* =========================================================== 4 Examples */
let examplesLoaded = false;

async function initExamples() {
  if (examplesLoaded) return;
  examplesLoaded = true;
  const sel = $("#ex-select");
  try {
    const list = await api("/api/examples");
    sel.innerHTML = list.map(e =>
      `<option value="${esc(e.name)}">${String(e.number).padStart(2, "0")} · ${esc(e.name)}</option>`).join("");
    sel.addEventListener("change", () => loadExample(sel.value));
    loadExample(sel.value);
  } catch (err) { examplesLoaded = false; showError($("#ex-info"), err); }
}

function md(s) {  // README cells use `code` spans
  return esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
}

function markTagged(code, word, cls) {
  const marks = {};
  code.split("\n").forEach((l, i) => { if (l.includes(word)) marks[i + 1] = { cls }; });
  return marks;
}

async function loadExample(name) {
  $("#ex-result").innerHTML = "";
  try {
    const e = await api(`/api/examples/${encodeURIComponent(name)}`);
    $("#ex-info").innerHTML = `<div class="ex-info">
        <div><span class="k">Vulnerability</span>${md(e.vulnerability)}</div>
        <div><span class="k">Fix</span>${md(e.fix)}</div>
        <div><span class="k">CWE</span>${esc(e.cwe)}</div>
        <div><span class="k">Usage</span><code>${esc(e.usage)}</code></div>
        ${e.bug ? `<div class="bug"><span class="k">Bug</span>${esc(e.bug)}</div>` : ""}
      </div>`;
    $("#ex-vuln").innerHTML = codeView(e.vulnerable, markTagged(e.vulnerable, "BUG:", "high"));
    $("#ex-secure").innerHTML = codeView(e.secure, markTagged(e.secure, "FIX:", "good"));
    $("#ex-cases").innerHTML = e.cases.map(c => `
      <button class="case-btn" data-case="${esc(c.id)}">
        <b>${esc(c.id)}</b> ${esc(c.category)} · ${esc(c.description)}
        <small>expected: secure version should ${c.expect === "ACCEPT" ? "accept" : "reject"}</small>
      </button>`).join("");
    $("#ex-cases").querySelectorAll(".case-btn").forEach(b => b.addEventListener("click", () => runCase(name, b)));
  } catch (err) { showError($("#ex-info"), err); }
}

async function runCase(name, btn) {
  document.querySelectorAll(".case-btn").forEach(b => b.classList.toggle("active", b === btn));
  const out = $("#ex-result");
  loading(out, `Running ${btn.dataset.case} on 4 builds…`);
  try {
    const r = await api(`/api/examples/${encodeURIComponent(name)}/run`, { case: btn.dataset.case });
    const c = r.case;
    const input = [
      c.args.length ? `argv: ${c.args.map(a => `<code>${esc(a.length > 60 ? a.slice(0, 60) + `… (${a.length} chars)` : a)}</code>`).join(" ")}` : "",
      c.stdin ? `stdin: <code>${esc((c.stdin.length > 60 ? c.stdin.slice(0, 60) + `… (${c.stdin.length} chars)` : c.stdin).replace(/\n/g, "\\n"))}</code>` : "",
    ].filter(Boolean).join(" · ") || "no input";
    out.innerHTML = `
      <div class="q-section">
        <div class="q-head"><h3>${esc(c.id)} · ${esc(c.description)}</h3><span class="sent">${input}</span></div>
        ${runGrid(r.runs)}
        <div class="pass-line">
          <span class="badge ${r.pass ? "lvl-good" : "lvl-bad"}">${r.pass ? "PASS" : "FAIL"}</span>
          expected the secure build to <b>${c.expect === "ACCEPT" ? "accept" : "reject"}</b>, it
          ${r.secure_result === "ACCEPT" ? "accepted" : r.secure_result === "REJECT" ? "rejected" : "did something else"};
          secure + ASan ${r.runs[3].findings.length ? "reported an error" : "was clean"}.
        </div>
      </div>`;
  } catch (err) { showError(out, err); }
}

/* ----------------------------------------------------------- delegation */
document.addEventListener("click", e => {
  const j = e.target.closest("[data-jump]");
  if (j) jumpTo(j.dataset.jump);
});

/* ---------------------------------------------------------------- init */
(async function init() {
  try {
    const [info, samples] = await Promise.all([api("/api/info"), api("/api/samples")]);
    Object.assign(SAMPLES, samples);
    fillSelect($("#scan-sample"), Object.keys(samples.scan));
    fillSelect($("#rt-sample"), Object.keys(samples.runtime));
    fillSelect($("#in-sample"), Object.keys(samples.input));

    const warn = [];
    if (info.missing_binaries.length)
      warn.push(`Missing project programs (${info.missing_binaries.join(", ")}). Run <code>make all asan</code> for the Input Tester.`);
    if (!info.examples_built) warn.push("Examples are not built. Run <code>make examples</code>.");
    if (!info.tools.cppcheck) warn.push("cppcheck is not installed; the scanner uses its own rules only.");
    if (!info.tools.gcc) warn.push("gcc is not installed; the Runtime Check cannot compile code.");
    $("#warnings").innerHTML = warn.map(w => `<div class="alert error">${w}</div>`).join("");
  } catch (err) {
    showError($("#warnings"), err);
  }
})();
