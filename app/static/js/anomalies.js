(() => {
  "use strict";
  const { q, esc, dateTime, emptyState } = window.Parralax;
  let anomalies = [];
  let reports = [];

  const statusLabel = (status) => ({ anomaly: "Anomalie", error: "Erreur", unavailable: "Indisponible" })[status] || status;
  const statusBadge = (status) => status === "anomaly" ? "badge--warning" : "badge--archived";

  function renderAnomalies() {
    const content = q("#anomaly-content");
    const needle = q("#anomaly-filter").value.trim().toLocaleLowerCase("fr-FR");
    const visible = anomalies.filter((item) => !needle || [item.agent, item.domain, item.check_type, item.anomaly_code, item.status].some((value) => String(value ?? "").toLocaleLowerCase("fr-FR").includes(needle)));
    q("#anomaly-count").textContent = String(anomalies.length);
    content.setAttribute("aria-busy", "false");
    if (!visible.length) {
      content.innerHTML = emptyState(
        anomalies.length ? "Aucun résultat correspondant" : "Aucune anomalie active",
        anomalies.length ? "Modifiez votre recherche." : "Le dernier rapport de chaque agent ne contient aucun contrôle en anomalie.",
      );
      return;
    }
    content.innerHTML = `<table><caption>${visible.length} anomalie(s) active(s)</caption><thead><tr><th scope="col">Observation</th><th scope="col">Cible</th><th scope="col">Contrôle</th><th scope="col">État</th><th scope="col">Code</th><th scope="col">Diagnostic</th></tr></thead><tbody>${visible.map((item) => `<tr><td><strong>${esc(item.agent)}</strong><br><span class="muted">${esc(dateTime(item.collected_at))}</span></td><td>${esc(item.domain || "Hôte de l’agent")}</td><td><code>${esc(item.check_type)}</code></td><td><span class="badge ${statusBadge(item.status)}">${esc(statusLabel(item.status))}</span></td><td><code>${esc(item.anomaly_code || "—")}</code></td><td><details class="anomaly-output"><summary>Afficher la sortie</summary><pre>${esc(item.output || "Aucune sortie")}</pre></details></td></tr>`).join("")}</tbody></table>`;
  }

  function renderReports() {
    const content = q("#report-content");
    content.setAttribute("aria-busy", "false");
    const agents = new Set(reports.map((report) => report.agent));
    q("#agent-count").textContent = String(agents.size);
    q("#last-report").textContent = reports.length ? dateTime(reports[0].collected_at) : "Jamais";
    if (!reports.length) {
      content.innerHTML = emptyState("Aucun rapport reçu", "Installez puis planifiez un agent de diagnostic pour alimenter cette page.");
      return;
    }
    content.innerHTML = `<table><caption>${reports.length} rapport(s) récent(s)</caption><thead><tr><th scope="col">Collecte</th><th scope="col">Agent</th><th scope="col">Complétude</th><th scope="col">Contrôles</th><th scope="col">Anomalies</th><th scope="col">Détail</th></tr></thead><tbody>${reports.map((report) => `<tr><td class="muted">${esc(dateTime(report.collected_at))}</td><td><strong>${esc(report.agent)}</strong></td><td><span class="badge ${report.status === "success" ? "badge--success" : "badge--warning"}">${report.status === "success" ? "Complet" : "Partiel"}</span></td><td>${esc(report.check_count)}</td><td>${esc(report.anomaly_count)}</td><td><a href="/api/network-diagnostics/${encodeURIComponent(report.id)}">Voir le JSON</a></td></tr>`).join("")}</tbody></table>`;
  }

  async function load() {
    try {
      const [anomalyResponse, reportResponse] = await Promise.all([
        fetch("/api/anomalies/network?current_only=true&limit=500"),
        fetch("/api/network-diagnostics?limit=50"),
      ]);
      const [anomalyData, reportData] = await Promise.all([anomalyResponse.json(), reportResponse.json()]);
      if (!anomalyResponse.ok) throw Error(anomalyData.detail || "Chargement des anomalies impossible");
      if (!reportResponse.ok) throw Error(reportData.detail || "Chargement des rapports impossible");
      anomalies = anomalyData;
      reports = reportData;
      renderAnomalies();
      renderReports();
    } catch (error) {
      q("#anomaly-content").setAttribute("aria-busy", "false");
      q("#report-content").setAttribute("aria-busy", "false");
      q("#anomaly-content").innerHTML = emptyState("Anomalies indisponibles", error.message);
      q("#report-content").innerHTML = emptyState("Rapports indisponibles", error.message);
    }
  }

  q("#anomaly-filter").addEventListener("input", renderAnomalies);
  load();
})();
