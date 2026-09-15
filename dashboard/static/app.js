const pageCopy = {
  overview: ["Realtime Detection Dashboard", "Live sensor mode: reading packets from IDS ens33."],
  alerts: ["DDoS Alert Timeline", "Latest suspicious flows detected by the machine learning model."],
  traffic: ["Traffic Analysis", "Batch-level classification from live sensor traffic."],
  model: ["Model Runtime", "Random Forest and LightGBM models loaded from local joblib files."],
};

const statusEl = document.getElementById("system-status");
const totalFlowsEl = document.getElementById("total-flows");
const totalAttacksEl = document.getElementById("total-attacks");
const totalBenignEl = document.getElementById("total-benign");
const attackRateEl = document.getElementById("attack-rate");
const lastBatchEl = document.getElementById("last-batch");
const alertsEl = document.getElementById("alerts");
const alertsTableEl = document.getElementById("alerts-table");
const detailBatchEl = document.getElementById("detail-batch");
const detailRateEl = document.getElementById("detail-rate");
const detailStatusEl = document.getElementById("detail-status");
const detailInputEl = document.getElementById("detail-input");
const pageTitleEl = document.getElementById("page-title");
const pageSubtitleEl = document.getElementById("page-subtitle");
const modelPicker = document.getElementById("model-picker");
const modelDropdownButton = document.getElementById("model-dropdown-button");
const modelDropdownLabel = document.getElementById("model-dropdown-label");
const modelDropdownMenu = document.getElementById("model-dropdown-menu");
const modelAlgorithmEl = document.getElementById("model-algorithm");
const modelActiveEl = document.getElementById("model-active");
const startBtn = document.getElementById("start-btn");
const pauseBtn = document.getElementById("pause-btn");
const resetBtn = document.getElementById("reset-btn");
const chartCanvases = [
  document.getElementById("traffic-chart"),
  document.getElementById("traffic-detail-chart"),
];
let refreshTimer = null;

function drawChart(canvas, history) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const padding = 36;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;
  const maxValue = Math.max(1, ...history.map((item) => item.flows));

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "#dce2ea";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = padding + (chartHeight / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
  }

  const barGap = 6;
  const barWidth = Math.max(8, chartWidth / Math.max(history.length, 1) - barGap);

  history.forEach((item, index) => {
    const x = padding + index * (barWidth + barGap);
    const attackHeight = (item.attacks / maxValue) * chartHeight;
    const benignHeight = (item.benign / maxValue) * chartHeight;
    const baseY = height - padding;

    ctx.fillStyle = "#0f766e";
    ctx.fillRect(x, baseY - benignHeight, barWidth, benignHeight);

    ctx.fillStyle = "#c2410c";
    ctx.fillRect(x, baseY - benignHeight - attackHeight, barWidth, attackHeight);
  });

  ctx.fillStyle = "#647086";
  ctx.font = "16px Segoe UI, Arial";
  ctx.fillText("Benign", padding, 24);
  ctx.fillStyle = "#0f766e";
  ctx.fillRect(padding + 62, 13, 12, 12);
  ctx.fillStyle = "#647086";
  ctx.fillText("DDoS", padding + 96, 24);
  ctx.fillStyle = "#c2410c";
  ctx.fillRect(padding + 144, 13, 12, 12);
}

function renderAlerts(alerts) {
  if (!alerts.length) {
    const empty = '<div class="alert"><strong>No alerts yet</strong><p>Waiting for traffic classification.</p></div>';
    alertsEl.innerHTML = empty;
    alertsTableEl.innerHTML = empty;
    return;
  }

  alertsEl.innerHTML = alerts
    .map((alert) => `
      <div class="alert">
        <strong>#${alert.batch_no} ${alert.level} - ${alert.time}</strong>
        <p>${alert.message}</p>
        <small>${alert.source_ip} to ${alert.destination_ip}</small>
      </div>
    `)
    .join("");

  alertsTableEl.innerHTML = `
    <div class="table-row header">
      <span>Batch</span><span>Time</span><span>Level</span><span>Message</span><span>Source</span><span>Destination</span>
    </div>
    ${alerts.map((alert) => `
      <div class="table-row">
        <span>#${alert.batch_no}</span>
        <span>${alert.time}</span>
        <strong>${alert.level}</strong>
        <span>${alert.message}</span>
        <span>${alert.source_ip}</span>
        <span>${alert.destination_ip}</span>
      </div>
    `).join("")}
  `;
}

function switchTab(tabName) {
  document.querySelectorAll("nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-page").forEach((page) => {
    page.classList.toggle("active", page.id === `tab-${tabName}`);
  });

  const [title, subtitle] = pageCopy[tabName];
  pageTitleEl.textContent = title;
  pageSubtitleEl.textContent = subtitle;
}

function updateControls(data) {
  startBtn.disabled = data.running || data.simulation_finished;
  pauseBtn.disabled = !data.running;
  resetBtn.disabled = false;
}

function updateModelPicker(data) {
  if (!modelDropdownMenu || !data.available_models) return;

  const currentOptions = Array.from(modelDropdownMenu.querySelectorAll("button"))
    .map((option) => option.dataset.model)
    .join(",");
  const nextOptions = data.available_models.map((model) => model.key).join(",");

  if (currentOptions !== nextOptions) {
    modelDropdownMenu.innerHTML = data.available_models
      .map((model) => `
        <button class="model-dropdown-option" type="button" role="option" data-model="${model.key}">
          ${model.label}
        </button>
      `)
      .join("");

    modelDropdownMenu.querySelectorAll("button[data-model]").forEach((option) => {
      option.addEventListener("click", () => {
        closeModelDropdown();
        setModel(option.dataset.model);
      });
    });
  }

  modelDropdownLabel.textContent = data.active_model_label;
  modelDropdownMenu.querySelectorAll("button[data-model]").forEach((option) => {
    option.classList.toggle("active", option.dataset.model === data.active_model_key);
  });
  modelAlgorithmEl.textContent = data.active_model_label;
  modelActiveEl.textContent = data.active_model_label;
}

function setStatusClass(status) {
  const calmStatuses = ["Running", "Paused", "Idle", "Live Finished"];
  statusEl.className = calmStatuses.includes(status) ? "status normal" : "status danger";
}

async function refreshStats() {
  const response = await fetch("/api/stats");
  const data = await response.json();

  totalFlowsEl.textContent = data.total_flows.toLocaleString();
  totalAttacksEl.textContent = data.total_attacks.toLocaleString();
  totalBenignEl.textContent = data.total_benign.toLocaleString();
  attackRateEl.textContent = `${data.last_attack_rate}%`;
  lastBatchEl.textContent = `${data.last_batch.toLocaleString()} flows`;
  statusEl.textContent = data.status;
  setStatusClass(data.status);
  detailBatchEl.textContent = data.last_batch.toLocaleString();
  detailRateEl.textContent = `${data.last_attack_rate}%`;
  detailStatusEl.textContent = data.status;
  detailInputEl.textContent = data.input_source;

  chartCanvases.forEach((canvas) => drawChart(canvas, data.history));
  renderAlerts(data.alerts);
  updateControls(data);
  updateModelPicker(data);
}

async function sendControl(action) {
  const response = await fetch("/api/control", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });
  const data = await response.json();
  updateControls(data);
  updateModelPicker(data);
  await refreshStats();
}

async function setModel(modelKey) {
  const response = await fetch("/api/model", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: modelKey }),
  });

  if (!response.ok) {
    await refreshStats();
    return;
  }

  const data = await response.json();
  updateModelPicker(data);
  await refreshStats();
}

document.querySelectorAll("nav button[data-tab]").forEach((button) => {
  button.addEventListener("click", () => switchTab(button.dataset.tab));
});

startBtn.addEventListener("click", () => sendControl("start"));
pauseBtn.addEventListener("click", () => sendControl("pause"));
resetBtn.addEventListener("click", () => sendControl("reset"));
function openModelDropdown() {
  modelPicker.classList.add("open");
  modelDropdownButton.setAttribute("aria-expanded", "true");
}

function closeModelDropdown() {
  modelPicker.classList.remove("open");
  modelDropdownButton.setAttribute("aria-expanded", "false");
}

modelDropdownButton.addEventListener("click", () => {
  if (modelPicker.classList.contains("open")) {
    closeModelDropdown();
  } else {
    openModelDropdown();
  }
});

document.addEventListener("click", (event) => {
  if (!modelPicker.contains(event.target)) {
    closeModelDropdown();
  }
});

refreshStats();
refreshTimer = setInterval(refreshStats, 2000);

