(() => {
  "use strict";
  const { q, qa, esc, emptyState } = window.Parralax;
  const app = q("#comparison-app");
  const domainId = app.dataset.domainId;
  const result = q("#comparison-result");
  const status = q("#comparison-status");
  let latestRecordSets = [];

  const comparisonValue = (values) => values?.length ? values.map((value) => typeof value === "string" ? value : JSON.stringify(value)).join(", ") : "—";

  function updateCompareButton() {
    const selected = qa('input[name="comparison-source"]:checked').length;
    const button = q("#compare-button");
    button.disabled = selected < 2;
    button.textContent = selected < 2 ? "Sélectionnez au moins deux sources" : `Comparer ${selected} sources`;
  }

  function recordSetDetail(recordSet) {
    const sources = Object.keys(recordSet.sources);
    const label = { different: "Différent", missing: "Absent sur une source" }[recordSet.status] || "Identique";
    const rows = recordSet.field_differences.map((difference) => `<tr><th scope="row">${esc(difference.label)}</th>${sources.map((source) => `<td>${esc(comparisonValue(difference.values[source]))}</td>`).join("")}</tr>`).join("");
    const missing = recordSet.missing_from.length ? `<p class="text-danger">Absent chez : ${esc(recordSet.missing_from.join(", "))}</p>` : "";
    return `<details class="record-set"><summary><strong>${esc(recordSet.name)} · ${esc(recordSet.type)}</strong> — ${esc(label)}</summary>${missing}<div class="table-scroll"><table><caption>Comparaison de ${esc(recordSet.name)} ${esc(recordSet.type)}</caption><thead><tr><th scope="col">Champ</th>${sources.map((source) => `<th scope="col">${esc(source)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div></details>`;
  }

  function renderRecordSets() {
    const type = q("#record-type")?.value || "";
    const visible = latestRecordSets.filter((recordSet) => recordSet.status !== "identical" && (!type || recordSet.type === type));
    q("#record-sets").innerHTML = visible.length ? visible.map(recordSetDetail).join("") : emptyState("Aucun écart", "Aucun écart n’a été détecté pour ce type d’enregistrement.");
  }

  function renderComparison(data) {
    latestRecordSets = data.dns.record_sets || [];
    const summary = data.dns.record_set_summary || {};
    const types = [...new Set(latestRecordSets.map((recordSet) => recordSet.type))].sort();
    const errors = Object.entries(data.dns.errors || {}).map(([source, error]) => `<li><strong>${esc(source)}</strong> : ${esc(error)}</li>`).join("");
    result.innerHTML = `<section class="card"><h2>Résumé</h2><div class="summary-card"><div><span>Sources lues</span><strong>${esc(data.dns.sources_read.length)}</strong></div><div><span>Différences</span><strong>${esc(summary.different || 0)}</strong></div><div><span>Absences</span><strong>${esc(summary.missing || 0)}</strong></div><div><span>Identiques</span><strong>${esc(summary.identical || 0)}</strong></div></div></section><section class="card"><div class="result-tools"><label class="field">Type d’enregistrement<select id="record-type"><option value="">Tous les types</option>${types.map((type) => `<option value="${esc(type)}">${esc(type)}</option>`).join("")}</select></label></div><p class="muted">Les écarts sont regroupés par nom et type, puis par paramètres DNS applicables.</p><h2>Écarts détaillés</h2><div id="record-sets"></div></section>${errors ? `<section class="card"><h2 class="text-danger">Sources indisponibles</h2><ul class="error-list">${errors}</ul></section>` : ""}`;
    q("#record-type").addEventListener("change", renderRecordSets);
    renderRecordSets();
  }

  async function compareSelected() {
    const selected = qa('input[name="comparison-source"]:checked').map((input) => input.value);
    if (selected.length < 2) return;
    const button = q("#compare-button");
    button.disabled = true;
    status.textContent = `Analyse de ${selected.length} sources en cours…`;
    try {
      const query = `?${selected.map((sourceId) => `source_ids=${encodeURIComponent(sourceId)}`).join("&")}`;
      const response = await fetch(`/api/domains/${domainId}/comparison${query}`);
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Erreur inconnue");
      renderComparison(data);
      status.textContent = "Comparaison terminée.";
    } catch (error) {
      result.innerHTML = emptyState("Comparaison indisponible", error.message);
      status.textContent = "La comparaison a échoué.";
    } finally {
      updateCompareButton();
    }
  }

  async function loadDomain() {
    try {
      const response = await fetch(`/api/domains/${domainId}`);
      const domain = await response.json();
      if (!response.ok) throw Error(domain.detail || "Domaine introuvable");
      document.title = `Comparateur · ${domain.name} · Parralax-DNS`;
      q("#page-title").textContent = `Comparateur · ${domain.name}`;
      q("#domain-breadcrumb").textContent = domain.name;
      const sources = domain.sources || [];
      q("#source-help").textContent = `${sources.length} source(s) disponible(s). Toutes sont sélectionnées par défaut.`;
      q("#source-picker").innerHTML = sources.map((source) => `<label class="source-option"><input type="checkbox" name="comparison-source" value="${esc(source.id)}" checked><span><strong>${esc(source.provider)}</strong><br><span class="muted">${esc(source.external_id)}</span></span></label>`).join("");
      qa('input[name="comparison-source"]').forEach((input) => input.addEventListener("change", updateCompareButton));
      if (sources.length < 2) {
        q("#source-help").textContent = "La comparaison nécessite au moins deux sources pour ce domaine.";
        result.innerHTML = emptyState("Comparaison indisponible", "Ajoutez une seconde source à ce domaine pour lancer une comparaison.");
        return;
      }
      q("#picker-actions").hidden = false;
      updateCompareButton();
      compareSelected();
    } catch (error) {
      q("#source-help").textContent = "Impossible de charger le domaine.";
      result.innerHTML = emptyState("Domaine indisponible", error.message);
    }
  }

  q("#select-all").addEventListener("click", () => { qa('input[name="comparison-source"]').forEach((input) => { input.checked = true; }); updateCompareButton(); });
  q("#select-none").addEventListener("click", () => { qa('input[name="comparison-source"]').forEach((input) => { input.checked = false; }); updateCompareButton(); });
  q("#compare-button").addEventListener("click", compareSelected);
  loadDomain();
})();
