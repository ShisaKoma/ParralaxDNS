(() => {
  "use strict";

  const q = (selector, root = document) => root.querySelector(selector);
  const qa = (selector, root = document) => [...root.querySelectorAll(selector)];
  const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
  const dateTime = (value) => value
    ? new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "medium" })
    : "Jamais";
  const uiWriteHeaders = { "X-Parralax-UI-Request": "1" };

  function emptyState(title, description = "", action = "") {
    return `<div class="empty-state" data-ui="empty-state"><span class="empty-state__icon" aria-hidden="true">◇</span><h2>${esc(title)}</h2>${description ? `<p>${esc(description)}</p>` : ""}${action}</div>`;
  }

  function showMessage(message, variant = "info") {
    const info = q("#message");
    const error = q("#error-message");
    if (!info || !error) return;
    info.hidden = true;
    error.hidden = true;
    const target = variant === "danger" ? error : info;
    target.className = `flash flash--${variant}`;
    target.textContent = message;
    target.hidden = !message;
  }

  window.Parralax = { q, qa, esc, dateTime, emptyState, showMessage, uiWriteHeaders };

  const tools = q("#tools");
  qa("[data-open-dialog]").forEach((button) => button.addEventListener("click", () => {
    if (tools) tools.open = false;
    const dialog = document.getElementById(button.dataset.openDialog);
    if (!dialog) return;
    dialog.showModal();
    if (dialog.id === "schedule-dialog") loadSchedule();
    if (dialog.id === "diagnostics-dialog") loadConnectivity();
    if (dialog.id === "setup-dialog" && !q("#collector-url").value && location.protocol === "https:") {
      q("#collector-url").value = location.origin;
    }
  }));
  qa("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => {
    document.getElementById(button.dataset.closeDialog)?.close();
  }));
  document.addEventListener("click", (event) => {
    if (tools && !tools.contains(event.target)) tools.open = false;
  });

  async function loadSchedule() {
    const panel = q("#schedule");
    panel.innerHTML = '<p class="muted">Chargement de la planification…</p>';
    try {
      const response = await fetch("/api/sync-schedule");
      const data = await response.json();
      if (!response.ok) throw Error(data.detail);
      if (!data.enabled) {
        panel.innerHTML = '<p class="muted">La synchronisation automatique est désactivée. Définissez <code>SYNC_INTERVAL_MINUTES</code> puis redémarrez le service.</p>';
        return;
      }
      const cadence = data.interval_minutes ? `Toutes les ${esc(data.interval_minutes)} minute(s).` : "Au démarrage uniquement.";
      const next = data.next_run_at ? ` Prochaine exécution : ${esc(dateTime(data.next_run_at))}.` : "";
      const last = data.last_completed_at ? ` Dernier résultat : ${esc(data.last_status || "inconnu")} · ${esc(dateTime(data.last_completed_at))}.` : " En attente de la première exécution.";
      panel.innerHTML = `<p><span class="badge ${data.running ? "badge--pending" : ""}">${data.running ? "En cours" : "Planifiée"}</span> ${cadence}${next}${last}</p><p class="muted">Les collecteurs externes sont planifiés depuis leurs serveurs source.</p>`;
    } catch (error) {
      panel.innerHTML = `<p class="text-danger">Impossible de lire la planification : ${esc(error.message)}</p>`;
    }
  }

  function connectivityCard(item) {
    const test = item.last_test;
    const label = test ? (test.status === "success" ? "Connexion réussie" : "Échec du test") : (item.configured ? "Pas encore testé" : "Non configuré");
    const badge = test?.status === "success" ? "badge--success" : "badge--pending";
    const details = test
      ? (test.status === "success" ? `<pre>${esc(JSON.stringify(test.response_preview, null, 2))}</pre>` : `<p class="text-danger">${esc(test.error_message || "Erreur inconnue")}</p>`)
      : `<p class="muted">${item.configured ? "Exécutez le test pour vérifier les droits." : "Ajoutez les variables d’environnement nécessaires puis redémarrez le service."}</p>`;
    return `<article class="connector"><header><div><h3>${esc(item.provider)}</h3><span class="badge ${badge}">${esc(label)}</span></div>${item.configured ? `<button class="btn btn--secondary btn--small" type="button" data-rerun-provider="${esc(item.provider)}">Rejouer</button>` : ""}</header><p class="muted">Dernier test : ${esc(test ? dateTime(test.completed_at) : "jamais")}${test?.latency_ms !== null && test?.latency_ms !== undefined ? ` · ${esc(test.latency_ms)} ms` : ""}</p>${details}</article>`;
  }

  async function loadConnectivity() {
    const panel = q("#connectivity");
    try {
      const response = await fetch("/api/connectivity-tests");
      const data = await response.json();
      if (!response.ok) throw Error(data.detail);
      panel.innerHTML = `<h3>Connecteurs configurés</h3><p class="muted">Chaque test effectue une lecture non destructive et conserve un aperçu limité.</p><div class="connector-grid">${data.providers.map(connectivityCard).join("")}</div><p class="muted">${esc(data.windows_dns_note)}</p>`;
    } catch (error) {
      panel.innerHTML = `<p class="text-danger">Impossible de charger les diagnostics : ${esc(error.message)}</p>`;
    }
  }

  async function rerunConnectivity(provider) {
    const status = q("#diagnostic-message");
    status.textContent = `Test ${provider} en cours…`;
    try {
      const response = await fetch(`/api/connectivity-tests/${encodeURIComponent(provider)}/rerun`, { method: "POST", headers: uiWriteHeaders });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail);
      status.textContent = `${provider} : ${data.status === "success" ? "connexion réussie." : "échec — consultez le détail."}`;
      await loadConnectivity();
    } catch (error) {
      status.textContent = `Erreur de test : ${error.message}`;
    }
  }

  q("#connectivity")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-rerun-provider]");
    if (button) rerunConnectivity(button.dataset.rerunProvider);
  });
  q("#diagnostics")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const status = q("#diagnostic-message");
    button.disabled = true;
    status.textContent = "Tests des connecteurs en cours…";
    try {
      const response = await fetch("/api/connectivity-tests", { method: "POST", headers: uiWriteHeaders });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail);
      status.textContent = data.results.length ? data.results.map((item) => `${item.provider}: ${item.status}`).join(" · ") : "Aucun connecteur API n’est configuré.";
      await loadConnectivity();
    } catch (error) {
      status.textContent = `Erreur de test : ${error.message}`;
    } finally {
      button.disabled = false;
    }
  });

  qa("[data-sync]").forEach((button) => button.addEventListener("click", async () => {
    button.disabled = true;
    showMessage("Synchronisation en cours…");
    try {
      const response = await fetch("/api/sync", { method: "POST", headers: uiWriteHeaders });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail);
      showMessage(data.results.map((item) => `${item.provider}: ${item.status}${item.discovered !== undefined ? ` (${item.discovered} trouvés)` : ""}`).join(" · "), "success");
      document.dispatchEvent(new CustomEvent("parralax:inventory-refresh"));
    } catch (error) {
      showMessage(`Erreur : ${error.message}`, "danger");
    } finally {
      button.disabled = false;
    }
  }));

  let setupToken = "";
  function clearSetup() {
    setupToken = "";
    q("#setup-instructions").hidden = true;
    ["server-config", "collector-config", "token-value", "collector-command", "copy-status", "setup-status"].forEach((id) => { q(`#${id}`).textContent = ""; });
    q("#generate-token").textContent = "Générer le jeton et les instructions";
    q("#collector-download").removeAttribute("href");
  }
  q("#setup-dialog")?.addEventListener("close", clearSetup);
  q("#collector-kind")?.addEventListener("change", () => {
    clearSetup();
    const windows = q("#collector-kind").value === "windows";
    q("#source-field").hidden = windows;
    q("#collector-source-help").hidden = windows;
    q("#collector-source").disabled = windows;
  });
  ["collector-source", "collector-url"].forEach((id) => q(`#${id}`)?.addEventListener("input", () => {
    q("#collector-url").setCustomValidity("");
    clearSetup();
  }));
  const shellQuote = (value) => `'${value.replace(/'/g, `'"'"'`)}'`;
  q("#setup-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    let base;
    try {
      const url = new URL(q("#collector-url").value);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw Error();
      base = url.href.replace(/\/$/, "");
    } catch {
      q("#collector-url").setCustomValidity("Utilisez une URL HTTP ou HTTPS sans identifiants, paramètres ni fragment.");
      q("#collector-url").reportValidity();
      return;
    }
    if (!setupToken) {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      setupToken = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    const kind = q("#collector-kind").value;
    const windows = kind === "windows";
    const kubernetes = kind === "kubernetes";
    const source = q("#collector-source").value.trim().toLowerCase();
    q("#server-config").textContent = windows ? `WINDOWS_DNS_COLLECTOR_TOKEN=${setupToken}` : `CUSTOM_DNS_COLLECTOR_TOKENS='${JSON.stringify({ [source]: setupToken })}'`;
    q("#server-help").textContent = windows ? "Le jeton Windows est partagé par les collecteurs Windows de cette instance." : "Ajoutez cette entrée à CUSTOM_DNS_COLLECTOR_TOKENS en conservant les autres sources.";
    q("#collector-download").href = `/collectors/download/${windows ? "windows" : kind}`;
    q("#windows-token").hidden = !windows;
    q("#token-value").textContent = windows ? setupToken : "";
    q("#collector-help").textContent = windows ? "Placez le script et sa configuration sur le serveur DNS." : kubernetes ? "Appliquez le manifeste fourni dans le cluster." : "Installez bash, jq et curl, puis placez le script sur le serveur Plesk.";
    q("#collector-config").textContent = windows ? JSON.stringify({ apiBaseUrl: base, collectorTokenFile: "C:\\ProgramData\\Parralax-DNS\\collector.token", timeoutSeconds: 120, maxAttempts: 3, includeReverseLookupZones: false }, null, 2) : `PARRALAX_API_URL=${shellQuote(`${base}/api/collectors/custom-dns/sync`)}\nPARRALAX_SOURCE=${source}\nPARRALAX_SOURCE_TOKEN=${setupToken}`;
    q("#run-help").textContent = windows ? "Lancez le collecteur dans une console PowerShell administrateur :" : kubernetes ? "Créez le Secret, appliquez le manifeste puis lancez une exécution de contrôle :" : "Vérifiez d’abord la collecte sans envoi :";
    q("#collector-command").textContent = windows ? "& 'C:\\Program Files\\Parralax-DNS\\Sync-ParralaxDns.ps1' -ConfigPath 'C:\\ProgramData\\Parralax-DNS\\Sync-ParralaxDns.json' -Verbose" : kubernetes ? `kubectl -n parralax-dns create secret generic parralax-kubernetes-collector --from-literal=PARRALAX_API_URL=${shellQuote(`${base}/api/collectors/custom-dns/sync`)} --from-literal=PARRALAX_SOURCE=${shellQuote(source)} --from-literal=PARRALAX_SOURCE_TOKEN=${shellQuote(setupToken)}\nkubectl apply -f parralax-kubernetes-collector.yaml\nkubectl -n parralax-dns create job --from=cronjob/parralax-kubernetes-collector parralax-kubernetes-collector-check` : "chmod 0600 /etc/parralax-plesk-collector.env\n/opt/parralax-plesk-collector/collect-plesk-dns.sh --dry-run";
    q("#verify-help").textContent = windows ? "La commande envoie les zones du serveur à Parralax-DNS." : kubernetes ? "Consultez les logs du Job de contrôle." : "Vérifiez le JSON, puis relancez le script sans --dry-run.";
    q("#setup-instructions").hidden = false;
    q("#setup-status").textContent = "Instructions prêtes. Le jeton doit encore être activé dans Parralax-DNS.";
    q("#generate-token").textContent = "Actualiser les instructions";
    q("#setup-instructions").scrollIntoView({ block: "start", behavior: "smooth" });
  });
  qa("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
    const node = q(`#${button.dataset.copy}`);
    try {
      await navigator.clipboard.writeText(node.textContent);
      q("#copy-status").textContent = "Copié dans le presse-papiers.";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(node);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      q("#copy-status").textContent = "Copie automatique indisponible. Le texte a été sélectionné.";
    }
  }));
  q("#refresh-domains")?.addEventListener("click", () => {
    q("#setup-dialog").close();
    if (document.body.dataset.page === "domain-list") document.dispatchEvent(new CustomEvent("parralax:inventory-refresh"));
    else location.href = "/domains";
  });
})();
