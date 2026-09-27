# Agent de diagnostic réseau

Cet agent Bash lit une liste locale de domaines, exécute uniquement les
contrôles autorisés `dig`, `traceroute` et `netstat -rn`, puis envoie un rapport
historisé à Parralax-DNS. Il ne reçoit ni commande ni argument arbitraire du
serveur et ne modifie jamais l'inventaire DNS.

## Dépendances

Debian :

```bash
apt-get update
apt-get install --no-install-recommends bash curl jq dnsutils traceroute net-tools
```

Sur les versions Debian qui ne proposent plus le paquet virtuel `dnsutils`,
installer `bind9-dnsutils` à sa place.

Alpine :

```bash
apk add --no-cache bash curl jq bind-tools traceroute net-tools
```

## Installation

```bash
install -d -m 0750 /opt/parralax-network-diagnostics /etc/parralax-network-diagnostics
install -m 0750 collectors/network-diagnostics/collect-network-diagnostics.sh /opt/parralax-network-diagnostics/
install -m 0640 collectors/network-diagnostics/domains.example.txt /etc/parralax-network-diagnostics/domains.txt
install -m 0600 collectors/network-diagnostics/network-diagnostics.env.example /etc/parralax-network-diagnostics/agent.env
```

Dans l'environnement de l'API, associer l'identifiant exact de l'agent à son
jeton. Chaque agent doit avoir son propre secret :

```dotenv
NETWORK_DIAGNOSTIC_AGENT_TOKENS={"debian-edge-01":"remplacer-par-un-secret-distinct"}
```

Adapter ensuite `/etc/parralax-network-diagnostics/agent.env` et la liste de
domaines. Le fichier accepte un FQDN par ligne, les lignes vides et les lignes
commençant par `#`. Une entrée invalide ou plus de 360 domaines bloque la
collecte entière, ce qui évite de produire silencieusement un rapport incomplet.

Tester sans envoyer :

```bash
set -a
. /etc/parralax-network-diagnostics/agent.env
set +a
/opt/parralax-network-diagnostics/collect-network-diagnostics.sh --dry-run
```

Puis envoyer le premier rapport en retirant `--dry-run`. La réponse contient
l'identifiant du rapport, le nombre de contrôles et le nombre d'anomalies.

Exemple cron toutes les quinze minutes :

```cron
*/15 * * * * root set -a; . /etc/parralax-network-diagnostics/agent.env; set +a; /opt/parralax-network-diagnostics/collect-network-diagnostics.sh >>/var/log/parralax-network-diagnostics.log 2>&1
```

## Détection et collecte partielle

- `dig` signale `NXDOMAIN`, `SERVFAIL`, `REFUSED`, l'absence de réponse A et les
  erreurs d'exécution ;
- `traceroute` conserve la route observée et signale un code de sortie non nul ;
- `netstat -rn` collecte une fois par rapport la table de routage locale, sans
  lier artificiellement cette information à un domaine ;
- une commande facultative absente produit `tool_missing`, marque le rapport
  comme partiel et conserve tous les autres résultats.

Chaque sortie est tronquée à 16 Kio. Le jeton n'est jamais inclus dans le JSON
ni affiché. Utiliser HTTPS en production et limiter le fichier d'environnement
au compte qui exécute l'agent.
