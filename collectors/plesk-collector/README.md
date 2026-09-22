# Collecteur Plesk → Parralax-DNS

Ce collecteur Bash est prévu pour **Plesk Obsidian sous Linux**. Il lit la
liste des domaines avec `plesk bin domain --list`, puis les records de chacune
des zones avec `plesk bin dns --info <domaine>`. Il envoie ensuite un inventaire
normalisé à `POST /api/collectors/custom-dns/sync`.

Il ne modifie jamais Plesk. Le TTL n'est pas inclus : la sortie de
`plesk bin dns --info` ne le fournit pas. Les MX et SRV conservent leurs champs
`priority`, `weight` et `port`.

## Garanties de sûreté

- aucune requête HTTP n'est envoyée avant d'avoir lu **tous** les domaines et
  toutes les zones ;
- un échec de `domain --list`, de `dns --info`, une sortie de zone vide ou une
  ligne DNS non comprise annule tout le cycle ;
- une liste de domaines ou de zones vide est refusée ;
- le script n'envoie donc jamais une liste vide ni un inventaire partiel qui
  risquerait d'archiver des zones dans Parralax-DNS.

Cette politique est volontairement stricte : si une nouvelle version de Plesk
change le format de `dns --info`, le collecteur s'arrête et affiche la ligne à
adapter au lieu de publier des données douteuses.

## Installation

Copier ce dossier sur l'hôte Plesk, puis rendre le script exécutable :

```bash
chmod 0750 collect-plesk-dns.sh
```

`bash` (version 3 ou plus récente), `jq`, `curl` et la commande locale `plesk`
sont requis. Exécuter le collecteur avec un compte ayant le droit de lire tous
les domaines et leurs zones ; l'administrateur Plesk est normalement le plus
simple. Le script ne requiert pas de clé de l'API distante Plesk, puisqu'il
s'exécute sur son serveur.

Créer un fichier de configuration hors du dépôt, par exemple
`/etc/parralax-plesk-collector.env`, avec les valeurs de `.env.example`. Limiter
son accès :

```bash
install -m 0600 -o root -g root /dev/null /etc/parralax-plesk-collector.env
```

Puis exécuter un test sans publication :

```bash
set -a
. /etc/parralax-plesk-collector.env
set +a
./collect-plesk-dns.sh --dry-run
```

Vérifier le JSON produit, puis retirer `--dry-run` pour publier.

## Planification

Exemple de cron toutes les six heures (les permissions du fichier de
configuration doivent rester `0600`) :

```cron
17 */6 * * * root set -a; . /etc/parralax-plesk-collector.env; set +a; /opt/parralax-plesk-collector/collect-plesk-dns.sh >>/var/log/parralax-plesk-collector.log 2>&1
```

Le jeton `PARRALAX_SOURCE_TOKEN` est celui associé à `PARRALAX_SOURCE` dans
`CUSTOM_DNS_COLLECTOR_TOKENS` côté Parralax-DNS. L'URL de destination doit être
HTTPS et joignable depuis le serveur Plesk.

## Sortie Plesk prise en charge

La conversion attend le format ligne par ligne de `plesk bin dns --info`, par
exemple :

```text
example.org. A 192.0.2.42
example.org. MX 10 mail.example.org.
_sip._tcp.example.org. SRV 10 5 5060 sip.example.org.
```

Les records non-MX/SRV transmettent toute la partie droite comme `value`, ce
qui couvre notamment A, AAAA, CNAME, NS, TXT, CAA, DS et HTTPS. Les records MX
et SRV doivent contenir leurs préfixes numériques standard ; autrement la
collecte est annulée.
