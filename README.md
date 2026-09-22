# Parralax-DNS

Application Python locale pour inventorier les domaines et zones gérés dans
Cloudflare, Infomaniak, OVHcloud et Technitium DNS, ainsi que les instances
proxy vues par NGINX Instance Manager. Une synchronisation est **non destructive** : une ressource absente
d'une collecte réussie est archivée localement, jamais supprimée.

## Fonctionnalités

- synchronisation manuelle depuis l'interface ;
- test de connectivité rejouable pour chaque API, avec latence et aperçu sûr de la réponse ;
- domaine ou ressource unifié(e) par nom, avec une ou plusieurs sources ;
- métadonnées brutes conservées, statut local, dates de première et dernière vue ;
- journal append-only des créations, mises à jour, archivages et restaurations ;
- page d’historique filtrable, qui présente le journal sans exposer les métadonnées brutes ;
- suivi d’un domaine avec les métadonnées actuelles reçues de chacune de ses sources ;
- conservation de la configuration DNS complète à chaque synchronisation et comparaison de deux états d’une même source ;
- comparaison à la demande des sources d’un même domaine (statuts et DNS) ;
- inventaire de plusieurs serveurs Microsoft DNS via un collecteur PowerShell ;
- ingestion sécurisée des zones et records de sources personnalisées (Plesk, cPanel ou outil interne) ;
- synchronisation des domaines OVHcloud et comparaison DNS à la demande ;
- synchronisation des zones et des records Technitium via `technitiumdns-api` ;
- inventaire en lecture seule des instances gérées par l’API native NGINX Instance Manager ;
- export BIND (`raw`) d'une zone Cloudflare et clonage explicite vers Infomaniak.

Le clonage crée une nouvelle zone Infomaniak à partir de l'export BIND de
Cloudflare. Il est volontairement une action distincte de la synchronisation et
requiert le droit `dns:write` côté Infomaniak. Il ne remplace jamais une zone
existante.

## Démarrage local

Python 3.14 ou une version ultérieure est requis.

```bash
cp .env.example .env
# renseigner les jetons, puis les exporter dans l'environnement de lancement
python -m venv .venv
.venv/bin/pip install -e .
set -a; source .env; set +a
.venv/bin/uvicorn app.main:app --reload
```

Ouvrir ensuite http://127.0.0.1:8000.

## Démarrage avec Docker

```bash
cp .env.example .env
# renseigner au moins un jeton API dans .env
docker compose up --build -d
docker compose ps
```

L'application est accessible uniquement depuis cette machine sur
http://127.0.0.1:8080 (ou le port défini dans `APP_PORT`). La base SQLite est conservée dans le volume Docker
`domain_inventory_data` : `docker compose down` ne l'efface pas. Pour suivre
le démarrage, exécuter `docker compose logs -f`; pour arrêter le service,
`docker compose down`.

> Pour une exposition réseau ou une production, placez l'application derrière
> un proxy HTTPS avec authentification (SSO ou équivalent). Elle est ici limitée
> à `127.0.0.1` afin de mener les tests sans rendre l'inventaire accessible au
> réseau local.

## PostgreSQL et migrations

La persistance utilise SQLAlchemy 2.x et une migration Alembic versionnée. La
variable `DATABASE_URL` est prioritaire sur `DATABASE_PATH` : SQLite reste le
choix de développement par défaut et PostgreSQL est adapté à la production.
Les documents de métadonnées et d'historique sont stockés en `JSONB` sous
PostgreSQL (avec un index GIN sur les métadonnées de sources) et en JSON sous
SQLite.

Pour démarrer la pile PostgreSQL de développement :

```bash
cp .env.example .env
docker compose -f compose.yaml -f compose.postgres.yaml up --build -d
docker compose -f compose.yaml -f compose.postgres.yaml ps
```

PostgreSQL est alors exposé uniquement sur `127.0.0.1:5433`. Les valeurs de
`POSTGRES_*` de `.env.example` sont exclusivement destinées au développement.
Utilisez un secret fort hors du dépôt dans tout autre environnement.

La pile de développement utilise PostgreSQL 18. Cette version emploie un
répertoire `PGDATA` propre à chaque version majeure ; le volume Compose est donc
monté sur `/var/lib/postgresql`. Un volume créé avec PostgreSQL 16 ne peut pas
être réutilisé directement par PostgreSQL 18. Exportez-le puis restaurez-le dans
la nouvelle instance (ou effectuez un `pg_upgrade`) avant de basculer un
environnement existant. Le volume `domain_inventory_postgres_18_data` est neuf
afin de ne pas démarrer PostgreSQL 18 sur des fichiers PostgreSQL 16.

En production, exécutez les migrations avec un compte technique distinct ayant
les droits DDL, puis démarrez l'application avec un compte ne disposant que des
droits `CONNECT`, `USAGE` sur le schéma, `SELECT/INSERT/UPDATE/DELETE` sur les
tables et `USAGE/SELECT` sur les séquences. Positionnez `RUN_MIGRATIONS=false`
pour empêcher le processus web d'appliquer du DDL. Une URL de production doit
imposer TLS, par exemple avec `sslmode=verify-full` et le certificat CA fourni
hors du dépôt.

```bash
# exécuté une seule fois par le compte de migration
DATABASE_URL='postgresql+psycopg://parralax_migrator:…@db.example.net/parralax?sslmode=verify-full' \
  .venv/bin/alembic upgrade head

# configuration du service web
DATABASE_URL='postgresql+psycopg://parralax_app:…@db.example.net/parralax?sslmode=verify-full'
RUN_MIGRATIONS=false
```

### Transfert d'un inventaire SQLite existant

Le transfert ne modifie jamais la source SQLite. Il exige une cible PostgreSQL
vide, crée d'abord une copie de sauvegarde de SQLite, conserve les identifiants
et l'historique, contrôle les volumes de chaque table et recale les séquences
PostgreSQL avant de déclarer le succès.

```bash
.venv/bin/python -m app.migrate_sqlite_to_postgres \
  --source /chemin/vers/domain_inventory.sqlite3 \
  --target 'postgresql+psycopg://parralax_migrator:…@db.example.net/parralax?sslmode=verify-full' \
  --backup-dir /chemin/hors-du-depot/parralax-dns-backups
```

Pour un retour arrière sans perte, garder SQLite et sa copie de sauvegarde,
mettre les synchronisations et clonages en pause pendant la validation, puis
repositionner `DATABASE_URL` sur SQLite si nécessaire. Une fois des écritures
acceptées sur PostgreSQL, elles doivent être rejouées avant tout retour à
SQLite ; ne supprimez donc jamais la source avant la fin de la période de
validation.

Les tests locaux utilisent SQLite. Pour ajouter les vérifications PostgreSQL,
fournissez une base dédiée et jetable via `POSTGRES_TEST_URL` :

```bash
POSTGRES_TEST_URL='postgresql+psycopg://parralax_dns:…@127.0.0.1:5433/parralax_dns' \
  .venv/bin/python -m unittest discover -s tests -v
```

## Collecte Microsoft DNS Server

Chaque serveur Windows est une source indépendante (`windows_dns:nom-du-serveur`).
Cela permet de comparer les zones et enregistrements entre serveurs, y compris
dans les scénarios de DNS fractionné ou de stratégies DNS.

1. Définir une valeur aléatoire forte pour `WINDOWS_DNS_COLLECTOR_TOKEN` dans
   `.env`, puis recréer le conteneur (`docker compose up -d --force-recreate`).
2. Publier Parralax-DNS derrière HTTPS et une authentification réseau adaptée. Le
   port local Docker n'est pas accessible directement depuis les serveurs Windows.
3. Copier le contenu de `collectors/windows-dns` dans
   `C:\Program Files\Parralax-DNS` sur chaque serveur DNS. Le collecteur est
   autonome : il utilise uniquement Windows PowerShell 5.1 et le module
   `DnsServer` installé avec le rôle DNS, sans Python ni installation du projet.
4. Copier `Sync-ParralaxDns.example.json` vers
   `C:\ProgramData\Parralax-DNS\Sync-ParralaxDns.json`, puis adapter au minimum
   `apiBaseUrl`. Par défaut, l'identifiant envoyé est `%COMPUTERNAME%` ; la
   propriété facultative `serverName` permet de le remplacer par un nom unique
   et stable.
5. Enregistrer le jeton dans le fichier indiqué par `collectorTokenFile`. Ce
   fichier doit être lisible seulement par le compte de la tâche planifiée et
   les administrateurs ; le jeton ne figure ainsi ni dans le JSON ni dans la
   ligne de commande.

Exemple de préparation du secret pour une tâche exécutée sous `SYSTEM`, depuis
une console PowerShell administrateur :

```powershell
$dataDirectory = 'C:\ProgramData\Parralax-DNS'
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
$secret = Read-Host 'Jeton WINDOWS_DNS_COLLECTOR_TOKEN' -AsSecureString
$secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer) |
        Set-Content "$dataDirectory\collector.token" -NoNewline -Encoding UTF8
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
}
icacls "$dataDirectory\collector.token" /inheritance:r /grant:r 'SYSTEM:(R)' 'BUILTIN\Administrators:(F)'
```

Tester ensuite l'exécution autonome. `-Verbose` affiche la progression sans
jamais écrire le jeton :

```powershell
& 'C:\Program Files\Parralax-DNS\Sync-ParralaxDns.ps1' `
  -ConfigPath 'C:\ProgramData\Parralax-DNS\Sync-ParralaxDns.json' -Verbose
```

Une réponse avec `status = success` confirme que l'API a accepté et persisté
l'inventaire. Le script renvoie un code d'échec PowerShell si la configuration,
la lecture DNS ou l'envoi échoue. Les erreurs réseau et réponses HTTP 408, 429
ou 5xx sont retentées avec un délai progressif. Les erreurs 400/401 ne sont pas
retentées afin de rendre immédiatement visible une mauvaise configuration.

Exemple de tâche planifiée toutes les 15 minutes sous `SYSTEM` :

```powershell
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "C:\Program Files\Parralax-DNS\Sync-ParralaxDns.ps1" -ConfigPath "C:\ProgramData\Parralax-DNS\Sync-ParralaxDns.json"'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 15)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'Parralax-DNS Collector' -Action $action `
    -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest
```

Le script lit par défaut les zones de recherche directe, leurs enregistrements
et leurs stratégies, puis transmet un instantané JSON par HTTPS à
`POST /api/collectors/windows-dns/sync`. `includeReverseLookupZones` permet
d'ajouter les zones inverses. `timeoutSeconds` et `maxAttempts` règlent le
comportement réseau. Une collecte complète réussie archive uniquement les zones
absentes de **ce serveur**, sans toucher aux autres sources. Le jeton peut aussi
être fourni par la variable d'environnement machine
`PARRALAX_DNS_COLLECTOR_TOKEN`; `-CollectorToken` reste disponible uniquement pour
un test interactif ponctuel.

## Collecte OVHcloud

Renseigner `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET` et
`OVH_CONSUMER_KEY` dans `.env`. Créer ces clés dans le portail OVHcloud avec des
droits de lecture limités à `/domain/*` et `/domain/zone/*`, puis relancer la
synchronisation dans Parralax-DNS. Les trois secrets restent uniquement dans
`.env` et ne sont jamais inscrits en base.

## Collecte Technitium DNS

Renseigner `TECHNITIUM_DNS_API_URL` et `TECHNITIUM_DNS_API_TOKEN`. Le
connecteur utilise le client Python `technitiumdns-api`, en authentification
Bearer uniquement (le jeton n'est jamais ajouté à l'URL). Créer un jeton dédié
avec les permissions minimales `Zones: View` et `Zone: View`. Chaque zone et
ses records sont synchronisés ; `TECHNITIUM_DNS_NODE=cluster` active la lecture
agrégée d'un cluster. Garder `TECHNITIUM_DNS_VERIFY_TLS=true` en production.

## Collecte NGINX Instance Manager

Renseigner `NGINX_NIM_URL` et soit `NGINX_NIM_API_TOKEN` (JWT recommandé), soit
`NGINX_NIM_USERNAME` et `NGINX_NIM_PASSWORD` pour l'authentification Basic.
Le connecteur appelle uniquement `GET /api/platform/{version}/instances`, avec
`v2` par défaut (modifiable par `NGINX_NIM_API_VERSION`), et conserve l'état et
les métadonnées des instances gérées. NIM n'est pas une autorité DNS : ses
instances sont donc inventoriées, mais ne sont pas comparées comme des zones
DNS. Utiliser un rôle NIM limité à la consultation des instances et conserver
`NGINX_NIM_VERIFY_TLS=true` hors environnement de test.

## Diagnostic des API

Le bouton **Tester les API** vérifie chaque connecteur configuré par une lecture
non destructive de son inventaire. L'interface conserve l'horodatage, la
latence, le statut et un aperçu normalisé (compte et cinq domaines au maximum).
Les métadonnées brutes, les contacts et les secrets ne sont ni affichés ni
enregistrés dans l'historique de ces tests. Le bouton **Rejouer** relance le
test d'un seul fournisseur avec sa configuration courante.

Les serveurs Windows DNS fonctionnent en mode collecteur initié par le serveur :
leur test de connectivité doit donc être lancé depuis PowerShell, qui envoie
ensuite sa collecte à Parralax-DNS.

## Synchronisation automatique

Parralax-DNS peut synchroniser automatiquement les connecteurs qu’il interroge
directement : Cloudflare, Infomaniak, OVHcloud, Technitium DNS et NGINX Instance
Manager. Définir l’intervalle dans
`.env`, puis recréer le conteneur :

```dotenv
# Toutes les 6 heures. 0 désactive le planificateur.
SYNC_INTERVAL_MINUTES=360
# Facultatif : exécute aussi une synchronisation non bloquante juste après le démarrage.
AUTO_SYNC_ON_STARTUP=true
```

```bash
docker compose -f compose.yaml -f compose.postgres.yaml up -d --force-recreate
```

L’interface affiche l’état du planificateur, l’heure de la prochaine exécution
et le dernier résultat. Les runs portent l’origine `scheduled` dans la base et
sont donc distinguables des actions `manual` et des remontées `collector` dans
l’historique. Une exécution concurrente est ignorée plutôt que de lancer deux
synchronisations en parallèle.

Les trois serveurs Windows DNS et les sources Plesk/cPanel restent des
collecteurs **push** : planifier leur script ou leur intégration sur l’hôte
source. Leur publication complète alimente le même historique. Pour un
déploiement avec plusieurs réplicas web, ne démarrer le planificateur que dans
une seule réplique ; un ordonnanceur externe ou un verrou distribué sera requis
avant de le dupliquer.

## Guide et test de l’API

En développement, le lien **Guide API** dans l’interface ouvre Swagger sur
`/api/docs`. Il décrit les schémas, permet de copier les requêtes et d’exécuter
un essai avec **Try it out**. Le schéma OpenAPI est disponible sur
`/api/openapi.json` pour générer un client.

`API_DOCS_ENABLED=false` désactive les deux routes. En production, les laisser
désactivées ou les placer derrière l’authentification SSO/proxy ; Swagger expose
les opérations d’administration et de collecte, même s’il ne contient aucun
secret.

## Sources DNS personnalisées (Plesk, cPanel, interne)

Un outil externe pousse son inventaire complet vers
`POST /api/collectors/custom-dns/sync`. Chaque `source` possède son propre jeton
dans `CUSTOM_DNS_COLLECTOR_TOKENS`, une map JSON gardée hors du dépôt :

```dotenv
CUSTOM_DNS_COLLECTOR_TOKENS={"plesk-prod-01":"un-secret-long-et-aleatoire","cpanel-prod-01":"un-autre-secret"}
```

Le client envoie ce secret dans l’en-tête `X-Parralax-Source-Token` et emploie le
format décrit dans Swagger. Un exemple minimal est :

```bash
curl --fail-with-body -X POST http://127.0.0.1:8080/api/collectors/custom-dns/sync \
  -H 'Content-Type: application/json' \
  -H 'X-Parralax-Source-Token: un-secret-long-et-aleatoire' \
  --data '{
    "source": "plesk-prod-01",
    "zones": [{
      "name": "example.org",
      "external_id": "plesk-zone-42",
      "remote_status": "active",
      "records": [
        {"name":"@","type":"MX","value":"mail.example.org","priority":10,"ttl":3600},
        {"name":"www","type":"A","value":"192.0.2.42","ttl":300}
      ]
    }]
  }'
```

Une publication doit contenir l’inventaire complet de cette source. Si une zone
précédemment connue n’y apparaît plus, elle est **archivée pour cette source
uniquement** ; elle n’est jamais supprimée ni archivée chez les autres sources.
Les records poussés sont inclus dans l’écran de comparaison, sans requête sortante
vers Plesk ou cPanel.

## Permissions API minimales

- Cloudflare : `Zone:Read` pour l'inventaire ; ajouter `DNS:Read` pour la
  comparaison DNS et l’export BIND. `DNS:Write` n’est pas requis.
- Infomaniak : `domain:read` pour l'inventaire et `dns:read` pour la
  comparaison DNS. Le clonage nécessite aussi `dns:write`.
- Microsoft DNS Server : exécuter le collecteur avec un compte ayant le droit de
  lecture du rôle DNS et utiliser un jeton de collecteur dédié.
- OVHcloud : une application API avec des droits de lecture sur les routes
  `/domain/*` et `/domain/zone/*`.
- Technitium DNS : un jeton dédié avec `Zones: View` et `Zone: View`.
- NGINX Instance Manager : un JWT ou compte dédié avec un rôle limité à la
  lecture des instances gérées.

Les appels employés sont `GET /zones` et `GET /zones/{id}/dns_records/export`
chez Cloudflare, ainsi que `GET /2/domains/domains` et `POST /2/zones/{zone}`
chez Infomaniak.

## Règle d'archivage

Une source n'est archivée qu'après que son fournisseur a renvoyé toutes ses
pages sans erreur. Ainsi, une panne API, une erreur d'autorisation ou une
collecte partielle ne peut pas provoquer d'archivage massif.
