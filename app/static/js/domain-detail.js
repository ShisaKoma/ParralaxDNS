(() => {
  "use strict";
  const { q, esc, dateTime, emptyState, showMessage, uiWriteHeaders } = window.Parralax;
  const root = q("#domain-detail");
  const domainId = root.dataset.domainId;
  let currentDomainName = "";

  const json = (value) => esc(JSON.stringify(value ?? {}, null, 2));
  const recordsFor = (metadata) => metadata?.dns_records ?? metadata?.records;

  function sourceCard(source) {
    const records = recordsFor(source.metadata);
    const configuration = { ...source.metadata };
    delete configuration.dns_records;
    delete configuration.records;
    delete configuration.dns_records_error;
    const recordContent = Array.isArray(records)
      ? `<details open><summary>Enregistrements DNS (${esc(records.length)})</summary><pre>${json(records)}</pre></details>`
      : (source.metadata?.dns_records_error ? `<p class="text-danger">Lecture DNS indisponible : ${esc(source.metadata.dns_records_error)}</p>` : '<p class="muted">Les enregistrements DNS seront disponibles après la prochaine synchronisation.</p>');
    return `<article class="metadata-card card"><h2>${esc(source.provider)}</h2><p class="muted">ID externe : ${esc(source.external_id)} · État : ${esc(source.remote_status || source.lifecycle_status || "—")}</p><details open><summary>Configuration du FQDN</summary><pre>${json(configuration)}</pre></details>${recordContent}<section id="snapshots-${esc(source.id)}" class="snapshot-controls" data-source-id="${esc(source.id)}"><p class="muted">Chargement des synchronisations…</p></section></article>`;
  }

  function snapshotLabel(snapshot) {
    return `${dateTime(snapshot.run_completed_at || snapshot.captured_at)} · ${snapshot.trigger || "manual"}`;
  }

  async function loadSourceSnapshots(source) {
    const panel = q(`#snapshots-${source.id}`);
    try {
      const response = await fetch(`/api/sources/${source.id}/snapshots`);
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Erreur inconnue");
      const snapshots = data.snapshots || [];
      if (snapshots.length < 2) {
        panel.innerHTML = '<p class="muted">La comparaison entre versions sera disponible après deux synchronisations de cette source.</p>';
        return;
      }
      const options = snapshots.map((snapshot) => `<option value="${esc(snapshot.sync_run_id)}">${esc(snapshotLabel(snapshot))}</option>`).join("");
      panel.innerHTML = `<h3>Comparer deux versions synchronisées</h3><label class="field">Version antérieure<select data-snapshot-select="before" id="before-${source.id}">${options}</select></label><label class="field">Version récente<select data-snapshot-select="after" id="after-${source.id}">${options}</select></label><button class="btn btn--primary" type="button" data-compare-snapshots="${source.id}">Comparer les versions</button><div id="snapshot-result-${source.id}"></div>`;
      q(`#before-${source.id}`).selectedIndex = 1;
      updateSnapshotButton(source.id);
    } catch (error) {
      panel.innerHTML = `<p class="text-danger">Impossible de charger les synchronisations : ${esc(error.message)}</p>`;
    }
  }

  function updateSnapshotButton(sourceId) {
    const disabled = q(`#before-${sourceId}`).value === q(`#after-${sourceId}`).value;
    const button = q(`[data-compare-snapshots="${sourceId}"]`);
    button.disabled = disabled;
    button.title = disabled ? "Choisissez deux synchronisations distinctes" : "";
  }

  function recordLines(records) {
    return records.length ? `<pre>${json(records)}</pre>` : '<p class="muted">Aucun enregistrement.</p>';
  }

  async function compareSourceSnapshots(sourceId) {
    const before = q(`#before-${sourceId}`).value;
    const after = q(`#after-${sourceId}`).value;
    const panel = q(`#snapshot-result-${sourceId}`);
    if (before === after) return;
    panel.innerHTML = '<p class="muted" role="status">Comparaison en cours…</p>';
    try {
      const response = await fetch(`/api/sources/${sourceId}/snapshots/compare?before_run_id=${encodeURIComponent(before)}&after_run_id=${encodeURIComponent(after)}`);
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Erreur inconnue");
      const comparison = data.comparison;
      const summary = comparison.summary;
      const changes = comparison.records.changed.map((change) => `<details><summary>${esc(change.name)} · ${esc(change.type)}</summary><p>Avant</p>${recordLines(change.before)}<p>Après</p>${recordLines(change.after)}</details>`).join("") || '<p class="muted">Aucune modification sur un nom et type existants.</p>';
      const configuration = comparison.configuration_changes.map((change) => `<details><summary>${esc(change.field)}</summary><p>Avant</p><pre>${json(change.before)}</pre><p>Après</p><pre>${json(change.after)}</pre></details>`).join("") || '<p class="muted">Aucune modification de configuration hors DNS.</p>';
      panel.innerHTML = `<div class="snapshot-result"><p><strong>${esc(summary.added)} ajouté(s) · ${esc(summary.removed)} supprimé(s) · ${esc(summary.changed)} modifié(s)</strong></p><h4>Ajoutés</h4>${recordLines(comparison.records.added)}<h4>Supprimés</h4>${recordLines(comparison.records.removed)}<h4>Modifiés</h4>${changes}<h4>Configuration du FQDN</h4>${configuration}</div>`;
    } catch (error) {
      panel.innerHTML = `<p class="text-danger" role="alert">Impossible de comparer les synchronisations : ${esc(error.message)}</p>`;
    }
  }

  function renderDomain(domain) {
    const sources = domain.sources || [];
    currentDomainName = domain.name;
    document.title = `${domain.name} · Parralax-DNS`;
    q("#page-title").textContent = domain.name;
    q("#domain-breadcrumb").textContent = domain.name;
    q("#source-count").textContent = String(sources.length);
    q("#domain-status").textContent = domain.lifecycle_status === "archived" ? "Archivé" : "Actif";
    q("#domain-metrics").hidden = false;
    const comparisonLink = q("#comparison-link");
    comparisonLink.hidden = sources.length < 2;
    comparisonLink.textContent = `Comparer les ${sources.length} sources`;
    q("#danger-zone").hidden = domain.lifecycle_status === "archived";
    root.setAttribute("aria-busy", "false");
    root.innerHTML = sources.length ? `<section class="metadata-grid" aria-label="Sources du domaine">${sources.map(sourceCard).join("")}</section>` : emptyState("Aucune source", "Ce domaine ne possède actuellement aucune source enregistrée.");
    sources.forEach(loadSourceSnapshots);
  }

  async function loadDomain() {
    root.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(`/api/domains/${encodeURIComponent(domainId)}`);
      const domain = await response.json();
      if (!response.ok) throw Error(domain.detail || "Domaine introuvable");
      renderDomain(domain);
    } catch (error) {
      root.setAttribute("aria-busy", "false");
      root.innerHTML = emptyState("Domaine indisponible", error.message);
    }
  }

  root.addEventListener("change", (event) => {
    const panel = event.target.closest("[data-source-id]");
    if (event.target.matches("[data-snapshot-select]") && panel) updateSnapshotButton(panel.dataset.sourceId);
  });
  root.addEventListener("click", (event) => {
    const button = event.target.closest("[data-compare-snapshots]");
    if (button) compareSourceSnapshots(button.dataset.compareSnapshots);
  });
  q("#archive-domain").addEventListener("click", async (event) => {
    if (!confirm(`Archiver ${currentDomainName} et toutes ses sources ?\n\nLes données et l’historique seront conservés.`)) return;
    const button = event.currentTarget;
    const status = q("#domain-action-status");
    button.disabled = true;
    status.textContent = "Archivage en cours…";
    try {
      const response = await fetch(`/api/domains/${encodeURIComponent(domainId)}/archive`, { method: "POST", headers: uiWriteHeaders });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Erreur inconnue");
      await loadDomain();
      showMessage("Le domaine et ses sources sont archivés. Les données restent consultables.", "success");
    } catch (error) {
      button.disabled = false;
      status.textContent = `Impossible d’archiver le domaine : ${error.message}`;
    }
  });
  loadDomain();
})();
