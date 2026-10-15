/**
 * AIORI-3 PS-011: Dashboard and Frontend Interactivity
 */

// Toast notification helper
function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = "toast";
  if (type === "success") toast.style.borderLeftColor = "#10b981";
  if (type === "error") toast.style.borderLeftColor = "#ef4444";
  if (type === "warning") toast.style.borderLeftColor = "#f59e0b";

  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Trigger Live Scan
async function startLiveScan() {
  const btn = document.getElementById("btn-live-scan");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning Scope...';
  }
  showToast("Initiating authorised scan across approved targets...", "info");

  try {
    const res = await fetch("/api/scan/start", { method: "POST" });
    const data = await res.json();
    if (data.status === "success") {
      showToast(`Scan complete! ${data.changes_count} changes, ${data.findings_count} findings.`, "success");
      setTimeout(() => window.location.reload(), 1200);
    } else {
      showToast(`Scan failed: ${data.message}`, "error");
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-play"></i> Start Authorised Scan';
      }
    }
  } catch (err) {
    showToast(`Error initiating scan: ${err}`, "error");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-play"></i> Start Authorised Scan';
    }
  }
}

// Trigger Seeded Issue Simulation Scan
async function triggerSeededSimulation() {
  const btn = document.getElementById("btn-simulate-scan");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating Seeded Drift...';
  }
  showToast("Running Seeded Issue demonstration scan...", "info");

  try {
    const res = await fetch("/api/scan/simulate", { method: "POST" });
    const data = await res.json();
    if (data.status === "success") {
      showToast("Seeded test scenario generated and analyzed!", "success");
      setTimeout(() => window.location.reload(), 1000);
    } else {
      showToast(`Simulation error: ${data.message}`, "error");
    }
  } catch (err) {
    showToast(`Simulation failure: ${err}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-flask"></i> Run Seeded Test Demo';
    }
  }
}

// Reset to Golden Baseline
async function resetGoldenBaseline() {
  if (!confirm("Reset to initial clean Golden Baseline snapshot (0 alerts)?")) return;
  try {
    const res = await fetch("/api/baseline/reset-golden", { method: "POST" });
    const data = await res.json();
    if (data.status === "success") {
      showToast("Baseline reset to Golden Standard.", "success");
      setTimeout(() => window.location.reload(), 1000);
    }
  } catch (err) {
    showToast("Failed to reset baseline: " + err, "error");
  }
}

// Modal management
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.style.display = "flex";
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.style.display = "none";
}

// Client-side table search filtering
function filterTable(inputId, tableId) {
  const input = document.getElementById(inputId);
  const filter = input.value.toLowerCase();
  const table = document.getElementById(tableId);
  if (!table) return;
  const rows = table.getElementsByTagName("tr");

  for (let i = 1; i < rows.length; i++) {
    const text = rows[i].textContent || rows[i].innerText;
    if (text.toLowerCase().indexOf(filter) > -1) {
      rows[i].style.display = "";
    } else {
      rows[i].style.display = "none";
    }
  }
}

// Initialize Charts on Dashboard
function initDashboardCharts(severityData, assetData) {
  // 1. Findings Severity Donut Chart
  const sevCanvas = document.getElementById("findingsSeverityChart");
  if (sevCanvas && typeof Chart !== "undefined") {
    new Chart(sevCanvas, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: severityData || [0, 0, 0, 0],
          backgroundColor: ["#ef4444", "#f97316", "#eab308", "#0ea5e9"],
          borderWidth: 2,
          borderColor: "#ffffff"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } }
        },
        cutout: "70%"
      }
    });
  }

  // 2. Asset Type Breakdown Bar Chart
  const assetCanvas = document.getElementById("assetDistributionChart");
  if (assetCanvas && typeof Chart !== "undefined") {
    new Chart(assetCanvas, {
      type: "bar",
      data: {
        labels: ["Domains", "Hosts", "Open Ports", "Findings"],
        datasets: [{
          label: "Count",
          data: assetData || [0, 0, 0, 0],
          backgroundColor: ["#1e3a8a", "#2563eb", "#3b82f6", "#f97316"],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: { beginAtZero: true, grid: { color: "#f1f5f9" } },
          x: { grid: { display: false } }
        }
      }
    });
  }
}
