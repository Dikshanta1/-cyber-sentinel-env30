const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const taskSelect = document.getElementById("taskSelect");
const resetBtn = document.getElementById("resetBtn");
const stepBtn = document.getElementById("stepBtn");
const commandInput = document.getElementById("commandInput");
const outputBox = document.getElementById("outputBox");
const rewardVal = document.getElementById("rewardVal");
const doneVal = document.getElementById("doneVal");

let trace = [];
let labels = [];
let chart;

function setStatus(ok, msg) {
  statusDot.className =
    "inline-block h-2 w-2 rounded-full " + (ok ? "bg-emerald-400" : "bg-rose-400");
  statusText.textContent = msg;
}

function extractReward(json) {
  const r = json?.reward;
  if (typeof r === "number") return r;
  if (r && typeof r === "object" && typeof r.score === "number") return r.score;
  return null;
}

async function apiGetState() {
  const res = await fetch("/state", { method: "GET" });
  if (!res.ok) throw new Error(`GET /state failed: ${res.status}`);
  return await res.json();
}

async function apiReset(taskName) {
  const res = await fetch("/reset", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ task_name: taskName }),
  });
  if (!res.ok) throw new Error(`POST /reset failed: ${res.status}`);
  return await res.json();
}

async function apiStep(command) {
  const res = await fetch("/step", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command }),
  });
  if (!res.ok) throw new Error(`POST /step failed: ${res.status}`);
  return await res.json();
}

function initChart() {
  const ctx = document.getElementById("rewardChart");
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "reward",
          data: trace,
          borderColor: "#22d3ee",
          backgroundColor: "rgba(34, 211, 238, 0.12)",
          fill: true,
          tension: 0.2,
          pointRadius: 2,
        },
      ],
    },
    options: {
      responsive: true,
      animation: false,
      scales: {
        y: { min: 0, max: 1 },
      },
      plugins: {
        legend: { display: false },
      },
    },
  });
}

function pushReward(r) {
  const idx = trace.length + 1;
  labels.push(String(idx));
  trace.push(r);
  chart.update();
}

function resetTrace() {
  trace.length = 0;
  labels.length = 0;
  chart.update();
}

async function doReset() {
  resetBtn.disabled = true;
  stepBtn.disabled = true;
  try {
    const task = taskSelect.value;
    const obs = await apiReset(task);
    outputBox.textContent = obs?.output ?? JSON.stringify(obs, null, 2);
    rewardVal.textContent = "—";
    doneVal.textContent = "—";
    resetTrace();
  } catch (e) {
    outputBox.textContent = String(e);
  } finally {
    resetBtn.disabled = false;
    stepBtn.disabled = false;
  }
}

async function doStep() {
  const cmd = (commandInput.value || "").trim();
  if (!cmd) return;
  stepBtn.disabled = true;
  try {
    const res = await apiStep(cmd);
    outputBox.textContent = res?.observation?.output ?? JSON.stringify(res, null, 2);
    const r = extractReward(res);
    rewardVal.textContent = r == null ? "—" : r.toFixed(3);
    doneVal.textContent = String(!!res?.done);
    if (typeof r === "number") pushReward(r);
  } catch (e) {
    outputBox.textContent = String(e);
  } finally {
    stepBtn.disabled = false;
  }
}

async function boot() {
  initChart();
  try {
    await apiGetState();
    setStatus(true, "API online");
  } catch (e) {
    setStatus(false, "API unreachable");
  }
}

resetBtn.addEventListener("click", doReset);
stepBtn.addEventListener("click", doStep);
commandInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") doStep();
});

document.querySelectorAll(".suggest").forEach((btn) => {
  btn.addEventListener("click", () => {
    commandInput.value = btn.getAttribute("data-suggest") || "";
    commandInput.focus();
  });
});

boot();

