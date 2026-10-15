const $ = (id) => document.getElementById(id);
const FALLBACK_SAMPLE_FILES = ["erp_q3_export.csv", "legacy_billing_q3.csv", "rbac_audit_log.json"];

function renderFileOptions(files) {
  const ul = $("file-list");
  ul.innerHTML = "";
  (files || []).forEach((f) => {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = f;
    checkbox.className = "pick-file";
    checkbox.checked = true;
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(f));
    li.appendChild(label);
    ul.appendChild(li);
  });
}

async function loadConfig() {
  const r = await fetch("/api/config");
  const j = await r.json();
  $("data-root").textContent = j.data_root || "(unknown)";
  renderFileOptions(j.files || []);
}

function setStatusBar(msg, isErr = false) {
  const el = $("status");
  el.textContent = msg;
  el.style.color = isErr ? "#fca5a5" : "#94a3b8";
}

function setBadge(text, cls) {
  const b = $("badge");
  if (!text) {
    b.classList.add("hidden");
    return;
  }
  b.textContent = text;
  b.classList.remove("hidden", "ok");
  if (cls) b.classList.add(cls);
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function selectedFiles() {
  return Array.from(document.querySelectorAll(".pick-file:checked")).map((x) => x.value);
}

$("btn-scan").addEventListener("click", async () => {
  const btn = $("btn-scan");
  btn.disabled = true;
  setStatusBar("Running local scans…");
  setBadge("", "");
  try {
    const chosen = selectedFiles();
    if (!chosen.length) throw new Error("Select at least one file to run full audit.");
    const r = await fetch("/api/scan/full", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selected_files: chosen }),
    });
    if (!r.ok) throw new Error(await r.text());
    const data = await r.json();
    $("output").textContent = pretty(data);
    const d = data.duplicate_group_count ?? 0;
    const rb = data.rbac_finding_count ?? 0;
    setBadge(`dup groups: ${d} · rbac: ${rb}`, d + rb === 0 ? "ok" : "");
    setStatusBar("Audit complete (outputs are PII-scrubbed).");
  } catch (e) {
    $("output").textContent = String(e);
    setStatusBar(String(e), true);
  } finally {
    btn.disabled = false;
  }
});

$("btn-alert").addEventListener("click", async () => {
  const btn = $("btn-alert");
  btn.disabled = true;
  setStatusBar("Privacy proxy + webhook…");
  try {
    const chosen = selectedFiles();
    if (!chosen.length) throw new Error("Select at least one file before sending alert.");
    const r = await fetch("/api/alert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        webhook_url: $("webhook").value.trim(),
        dry_run: $("dry-run").checked,
        selected_files: chosen,
      }),
    });
    const data = await r.json();
    $("output").textContent = pretty(data);
    if (!r.ok) setStatusBar("Alert endpoint returned error.", true);
    else setStatusBar(data.sent ? "Posted to webhook." : data.dry_run ? "Dry run OK." : "See JSON for details.");
  } catch (e) {
    $("output").textContent = String(e);
    setStatusBar(String(e), true);
  } finally {
    btn.disabled = false;
  }
});

loadConfig().catch((e) => {
  $("data-root").textContent = "Could not load /api/config. Using built-in sample file list.";
  renderFileOptions(FALLBACK_SAMPLE_FILES);
  setStatusBar("API unavailable. Start app with start.bat/start.ps1, then refresh.", true);
});
