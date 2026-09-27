(() => {
  "use strict";
  const { q, esc, dateTime, emptyState } = window.Parralax;
  const content = q("#history-content");
  let entries = [];

  function renderHistory() {
    const needle = q("#history-filter").value.trim().toLocaleLowerCase("fr-FR");
    const visible = entries.filter((entry) => !needle || [entry.domain_name, entry.source, entry.event_type, entry.trigger, entry.summary].some((value) => String(value ?? "").toLocaleLowerCase("fr-FR").includes(needle)));
    q("#history-count").textContent = entries.length === visible.length ? String(entries.length) : `${visible.length} / ${entries.length}`;
    content.setAttribute("aria-busy", "false");
    if (!visible.length) {
      content.innerHTML = emptyState("Aucun événement", entries.length ? "Modifiez votre recherche pour afficher d’autres événements." : "Le journal sera alimenté lors des prochaines synchronisations.");
      return;
    }
    content.innerHTML = `<table><caption>${visible.length} événement(s) affiché(s)</caption><thead><tr><th scope="col">Date</th><th scope="col">Domaine</th><th scope="col">Source</th><th scope="col">Origine</th><th scope="col">Événement</th><th scope="col">Détail</th></tr></thead><tbody>${visible.map((entry) => `<tr><td class="muted">${esc(dateTime(entry.occurred_at))}</td><td><a href="/domains/${entry.domain_id}"><strong>${esc(entry.domain_name)}</strong></a></td><td class="muted">${esc(entry.source || "Domaine unifié")}</td><td class="muted">${esc(entry.trigger || "action directe")}</td><td><span class="badge ${esc(entry.event_type)}">${esc(entry.event_type)}</span></td><td>${esc(entry.summary)}</td></tr>`).join("")}</tbody></table>`;
  }

  async function loadHistory() {
    try {
      const response = await fetch("/api/history?limit=200");
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Erreur inconnue");
      entries = data;
      renderHistory();
    } catch (error) {
      content.setAttribute("aria-busy", "false");
      content.innerHTML = emptyState("Historique indisponible", error.message);
    }
  }
  q("#history-filter").addEventListener("input", renderHistory);
  loadHistory();
})();
