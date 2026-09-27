(() => {
  "use strict";
  const { q, esc, dateTime, emptyState, showMessage, uiWriteHeaders } = window.Parralax;
  const content = q("#content");
  let inventory = [];
  const searchText = (value) => String(value ?? "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLocaleLowerCase("fr-FR");

  function renderInventory() {
    const query = searchText(q("#domain-search").value.trim());
    const sort = q("#domain-sort").value;
    const domains = inventory.filter((domain) => !query || searchText([domain.name, ...domain.sources.map((source) => `${source.provider} ${source.remote_status || ""}`)].join(" ")).includes(query));
    domains.sort((a, b) => {
      if (sort === "name-desc") return String(b.name).localeCompare(String(a.name), "fr", { numeric: true, sensitivity: "base" });
      if (sort === "last-seen-desc") return (Date.parse(b.last_seen_at) || 0) - (Date.parse(a.last_seen_at) || 0);
      if (sort === "sources-desc") return b.sources.length - a.sources.length || String(a.name).localeCompare(String(b.name), "fr", { numeric: true, sensitivity: "base" });
      return String(a.name).localeCompare(String(b.name), "fr", { numeric: true, sensitivity: "base" });
    });
    q("#domain-count").textContent = inventory.length === domains.length ? String(inventory.length) : `${domains.length} / ${inventory.length}`;
    content.setAttribute("aria-busy", "false");
    if (!domains.length) {
      const title = inventory.length ? "Aucun résultat" : (q("#archived").checked ? "Aucun domaine" : "Aucun domaine actif");
      const description = inventory.length ? "Modifiez la recherche ou les filtres pour afficher d’autres domaines." : "Connectez un serveur ou synchronisez un fournisseur API pour constituer l’inventaire.";
      const action = inventory.length ? "" : '<button class="btn btn--primary" type="button" data-empty-setup>Connecter mon premier serveur</button>';
      content.innerHTML = emptyState(title, description, action);
      return;
    }
    content.innerHTML = `<table><caption>${domains.length} domaine(s) affiché(s)</caption><thead><tr><th scope="col">Domaine</th><th scope="col">Sources</th><th scope="col">État</th><th scope="col">Dernière collecte</th><th scope="col">Actions</th></tr></thead><tbody>${domains.map((domain) => `<tr><td><strong>${esc(domain.name)}</strong></td><td>${domain.sources.map((source) => `<div class="source"><strong>${esc(source.provider)}</strong> <span class="muted">${esc(source.remote_status || "—")}</span>${source.provider === "cloudflare" ? `<br><a href="/api/sources/${source.id}/zone-file">Télécharger BIND</a> · <button class="link-button" type="button" data-clone-source="${source.id}">Cloner vers Infomaniak</button>` : ""}</div>`).join("")}</td><td><span class="badge ${domain.lifecycle_status === "archived" ? "badge--archived" : "badge--success"}">${domain.lifecycle_status === "archived" ? "Archivé" : "Actif"}</span></td><td class="muted">${esc(dateTime(domain.last_seen_at))}</td><td class="row-actions"><a href="/domains/${domain.id}">Voir le détail</a></td></tr>`).join("")}</tbody></table>`;
  }

  async function loadInventory() {
    content.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(`/api/domains?include_archived=${q("#archived").checked}`);
      if (!response.ok) throw Error("Chargement indisponible");
      inventory = await response.json();
      renderInventory();
    } catch (error) {
      content.setAttribute("aria-busy", "false");
      content.innerHTML = emptyState("Inventaire indisponible", "Les domaines n’ont pas pu être chargés.", '<button class="btn btn--primary" type="button" data-retry>Réessayer</button>');
    }
  }

  async function cloneZone(sourceId) {
    const target = prompt("Nouvelle zone Infomaniak à créer (elle ne doit pas déjà exister) :");
    if (!target || !confirm(`Créer la zone ${target} chez Infomaniak avec l’export BIND de Cloudflare ?`)) return;
    try {
      const response = await fetch(`/api/sources/${sourceId}/clone-to-infomaniak`, { method: "POST", headers: { ...uiWriteHeaders, "Content-Type": "application/json" }, body: JSON.stringify({ target_zone: target }) });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail);
      showMessage(`Zone ${data.target_zone} créée chez Infomaniak.`, "success");
    } catch (error) {
      showMessage(`Erreur de clonage : ${error.message}`, "danger");
    }
  }

  content.addEventListener("click", (event) => {
    if (event.target.closest("[data-retry]")) loadInventory();
    if (event.target.closest("[data-empty-setup]")) q("#setup-dialog").showModal();
    const clone = event.target.closest("[data-clone-source]");
    if (clone) cloneZone(clone.dataset.cloneSource);
  });
  q("#archived").addEventListener("change", loadInventory);
  q("#domain-search").addEventListener("input", renderInventory);
  q("#domain-sort").addEventListener("change", renderInventory);
  document.addEventListener("parralax:inventory-refresh", loadInventory);
  loadInventory();
})();
