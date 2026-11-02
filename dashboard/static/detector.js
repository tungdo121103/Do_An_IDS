const attackType = document.body.dataset.attackType;
const el = (id) => document.getElementById(id);
const fmt = (value) => Number(value || 0).toLocaleString();
const clock = (timestamp) => timestamp ? new Date(timestamp * 1000).toLocaleTimeString() : "No data";
const modelPicker = el("model-picker");

function drawBars(canvas, values, label, color) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const left = 40;
  const top = 40;
  const bottom = height - 30;
  const plotHeight = bottom - top;
  ctx.clearRect(0, 0, width, height);
  ctx.strokeStyle = "#e2e8f0";
  ctx.fillStyle = "#647086";
  ctx.font = "14px sans-serif";
  for (let i = 0; i <= 4; i++) {
    const y = bottom - plotHeight * i / 4;
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - 20, y); ctx.stroke();
  }
  ctx.fillStyle = color;
  ctx.fillRect(left, 10, 12, 12);
  ctx.fillStyle = "#647086";
  ctx.fillText(label, left + 18, 21);
  if (!values.length) {
    ctx.fillText("No data yet", left, top + 25);
    return;
  }
  const max = Math.max(1, ...values.map((item) => item.value));
  const slot = (width - left - 20) / values.length;
  values.forEach((item, index) => {
    const barHeight = item.value / max * plotHeight;
    ctx.fillStyle = color;
    ctx.fillRect(left + index * slot + 2, bottom - barHeight, Math.max(2, slot - 4), barHeight);
  });
}

function drawClassification(history) {
  const canvas = el("traffic-chart");
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const left = 40, top = 42, bottom = height - 30;
  const plotHeight = bottom - top;
  ctx.clearRect(0, 0, width, height);
  ctx.strokeStyle = "#e2e8f0";
  for (let i = 0; i <= 4; i++) {
    const y = bottom - plotHeight * i / 4;
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - 20, y); ctx.stroke();
  }
  const attackLabel = attackType === "ssh" ? "Flagged SSH" : "Flagged DDoS";
  const attackColor = attackType === "ssh" ? "#7c3aed" : "#c2410c";
  ctx.font = "14px sans-serif";
  ctx.fillStyle = "#0f766e"; ctx.fillRect(left, 10, 12, 12);
  ctx.fillStyle = "#647086"; ctx.fillText("Benign", left + 18, 21);
  ctx.fillStyle = attackColor; ctx.fillRect(left + 93, 10, 12, 12);
  ctx.fillStyle = "#647086"; ctx.fillText(attackLabel, left + 111, 21);
  if (!history.length) { ctx.fillText("No flows yet", left, top + 25); return; }
  const max = Math.max(1, ...history.map((row) => row.flows));
  const slot = (width - left - 20) / history.length;
  history.forEach((row, index) => {
    const x = left + index * slot + 2;
    const barWidth = Math.max(2, slot - 4);
    const benignHeight = row.benign / max * plotHeight;
    const attackHeight = row.attacks / max * plotHeight;
    ctx.fillStyle = "#0f766e"; ctx.fillRect(x, bottom - benignHeight, barWidth, benignHeight);
    ctx.fillStyle = attackColor; ctx.fillRect(x, bottom - benignHeight - attackHeight, barWidth, attackHeight);
  });
}

function renderAlerts(alerts) {
  const container = el("alerts");
  container.replaceChildren();
  if (!alerts.length) {
    const block = document.createElement("div");
    block.className = "alert";
    const title = document.createElement("strong");
    title.textContent = "No model alerts yet";
    const detail = document.createElement("p");
    detail.textContent = `Waiting for ${attackType.toUpperCase()} flow classification.`;
    block.append(title, detail);
    container.append(block);
    return;
  }
  alerts.forEach((alert) => {
    const block = document.createElement("div");
    block.className = "alert";
    const title = document.createElement("strong");
    title.textContent = `#${alert.batch_no} ${alert.level} · ${alert.time}`;
    const detail = document.createElement("p");
    detail.textContent = alert.message;
    const source = document.createElement("small");
    source.textContent = `${alert.source_ip} to ${alert.destination_ip}`;
    block.append(title, detail, source);
    container.append(block);
  });
}

function renderSsh(data) {
  const auth = data.ssh_auth;
  el("ssh-failed-total").textContent = fmt(auth.failed_passwords);
  el("ssh-failed-recent").textContent = fmt(auth.recent_failed_passwords);
  el("ssh-flow-total").textContent = fmt(data.total_flows);
  el("ssh-ml-total").textContent = fmt(data.total_attacks);
  el("ssh-ml-rate").textContent = `${data.flagged_rate}%`;
  el("ssh-ml-summary").textContent = `${fmt(data.total_attacks)} of ${fmt(data.total_flows)} SSH flows (${data.flagged_rate}%)`;
  el("ssh-model-name").textContent = data.active_model_label;
  el("ssh-last-failure").textContent = clock(auth.last_seen);
  el("ssh-last-alert").textContent = auth.last_log_alert ? clock(auth.last_log_alert.created_at) : "No log alert";
  drawBars(el("ssh-log-chart"), auth.timeline.map((row) => ({value: row.failures})), "Failed passwords", "#ea580c");

  let signal = "waiting", title = "Waiting for Victim SSH log";
  let detail = "Start the log agent on Victim before the SSH test.";
  let status = "Waiting";
  if (!auth.enabled) {
    title = "Victim log feed not configured";
    detail = "Set the same IDS_SSH_AUTH_TOKEN on IDS and Victim, then start the log agent.";
    status = "Not configured";
  } else if (auth.log_alert) {
    signal = "danger"; title = "Repeated SSH password failures in Victim log";
    detail = `At least ${auth.threshold} failures from one source in ${auth.window_seconds} seconds.`;
    status = "Repeated failures";
  } else if (auth.last_log_alert) {
    signal = "notice"; title = "SSH log alert recorded";
    detail = `${auth.last_log_alert.source_ip}: ${auth.last_log_alert.failed_passwords} failures in ${auth.last_log_alert.window_seconds} seconds at ${clock(auth.last_log_alert.created_at)}.`;
    status = "Alert recorded";
  } else if (auth.recent_failed_passwords > 0) {
    signal = "notice"; title = "SSH password failures observed";
    detail = `${auth.recent_failed_passwords} failures in the last ${auth.window_seconds} seconds.`;
    status = "Failures observed";
  } else if (auth.last_seen) {
    signal = "normal"; title = "No recent SSH password failures";
    detail = `Last failure received at ${clock(auth.last_seen)}. The agent may or may not still be running.`;
    status = "No recent failures";
  }
  el("ssh-log-signal").className = `ssh-signal ${signal}`;
  el("ssh-log-signal-title").textContent = title;
  el("ssh-log-signal-detail").textContent = detail;
  el("ssh-log-status").textContent = status;

  const sources = el("ssh-source-list");
  sources.replaceChildren();
  if (!auth.sources.length) {
    const empty = document.createElement("p"); empty.className = "empty-state";
    empty.textContent = "No failed logins received yet."; sources.append(empty);
  }
  auth.sources.forEach((source) => {
    const row = document.createElement("div"); row.className = "ssh-source-row";
    const identity = document.createElement("div");
    const ip = document.createElement("strong"); ip.textContent = source.ip;
    const note = document.createElement("small"); note.textContent = `${source.connections} source ports · last ${clock(source.last_seen)}`;
    identity.append(ip, note);
    const failures = document.createElement("strong"); failures.textContent = `${fmt(source.failures)} failures`;
    row.append(identity, failures); sources.append(row);
  });
}

function updateModelPicker(data) {
  el("model-dropdown-label").textContent = data.active_model_label;
  const menu = el("model-dropdown-menu");
  menu.replaceChildren();
  data.available_models.forEach((model) => {
    const option = document.createElement("button");
    option.className = `model-dropdown-option${model.active ? " active" : ""}`;
    option.type = "button"; option.setAttribute("role", "option");
    option.textContent = model.label;
    option.addEventListener("click", () => { closePicker(); setModel(model.key); });
    menu.append(option);
  });
}

function render(data) {
  const status = el("system-status");
  status.textContent = data.status;
  status.className = ["Running", "Paused", "Idle"].includes(data.status) ? "status normal" : "status danger";
  el("start-btn").disabled = data.running || data.simulation_finished;
  el("pause-btn").disabled = !data.running;
  el("last-batch").textContent = `${fmt(data.last_batch)} flows in last batch`;
  if (attackType === "ddos") {
    el("total-flows").textContent = fmt(data.total_flows);
    el("total-attacks").textContent = fmt(data.total_attacks);
    el("total-benign").textContent = fmt(data.total_benign);
    el("flagged-rate").textContent = `${data.flagged_rate}%`;
    el("last-rate").textContent = `${data.last_attack_rate}%`;
  } else renderSsh(data);
  drawClassification(data.history);
  renderAlerts(data.alerts);
  updateModelPicker(data);
}

async function refreshStats() {
  try {
    const response = await fetch(`/api/stats?attack_type=${attackType}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    el("system-status").textContent = "Data unavailable";
    el("system-status").className = "status danger";
    console.error(error);
  }
}

async function post(path, payload) {
  const response = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  render(await response.json());
}

async function sendControl(action) {
  try { await post("/api/control", {attack_type: attackType, action}); await refreshStats(); }
  catch (error) { console.error(error); el("system-status").textContent = "Control failed"; }
}
async function setModel(model) {
  try { await post("/api/model", {attack_type: attackType, model}); await refreshStats(); }
  catch (error) { console.error(error); el("system-status").textContent = "Model change failed"; }
}
function closePicker() { modelPicker.classList.remove("open"); el("model-dropdown-button").setAttribute("aria-expanded", "false"); }
el("model-dropdown-button").addEventListener("click", () => {
  const open = modelPicker.classList.toggle("open");
  el("model-dropdown-button").setAttribute("aria-expanded", String(open));
});
document.addEventListener("click", (event) => { if (!modelPicker.contains(event.target)) closePicker(); });
el("start-btn").addEventListener("click", () => sendControl("start"));
el("pause-btn").addEventListener("click", () => sendControl("pause"));
el("reset-btn").addEventListener("click", () => sendControl("reset"));
refreshStats();
setInterval(refreshStats, 2000);
