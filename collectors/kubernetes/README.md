# Collecteur Kubernetes → Parralax-DNS

Ce collecteur inventorie en lecture seule les hôtes configurés dans les objets
`networking.k8s.io/v1 Ingress` de tous les espaces de noms. Pour chaque hôte,
il remonte les adresses du statut du load balancer (`A`, `AAAA` ou `CNAME`) et,
le cas échéant, la cible de l’annotation ExternalDNS
`external-dns.alpha.kubernetes.io/target`.

Il ne lit pas les zones de CoreDNS, ne crée ni ne modifie de ressource et ne
déduit pas les hôtes des Services : un hôte absent des règles Ingress reste donc
hors de l’inventaire. Le rôle fourni accorde uniquement `list` sur les Ingress.

## Déployer

Construisez l’image et publiez-la dans votre registre de confiance. Épinglez
une version ou un digest dans le manifeste plutôt que de conserver `latest` en
production.

```bash
docker build -t registry.example.net/parralax/kubernetes-collector:1.0 collectors/kubernetes
docker push registry.example.net/parralax/kubernetes-collector:1.0
```

Dans `parralax-kubernetes-collector.yaml`, remplacez `image:` par cette image,
créez un espace de noms dédié si nécessaire, puis créez le Secret. Le jeton est
le jeton dédié à la source dans `CUSTOM_DNS_COLLECTOR_TOKENS` côté
Parralax-DNS ; ne le placez pas dans le manifeste ni dans Git.

```bash
kubectl create namespace parralax-dns
kubectl -n parralax-dns create secret generic parralax-kubernetes-collector \
  --from-literal=PARRALAX_API_URL='https://dns.example.net/api/collectors/custom-dns/sync' \
  --from-literal=PARRALAX_SOURCE='kubernetes-prod-01' \
  --from-literal=PARRALAX_SOURCE_TOKEN='un-jeton-long-et-aleatoire'
kubectl apply -f collectors/kubernetes/parralax-kubernetes-collector.yaml
```

Le CronJob s’exécute toutes les six heures sans concurrence. Son seul volume
inscriptible est un `emptyDir` temporaire destiné au cache de découverte et au
payload ; aucun volume contenant des données du cluster n’est monté. Pour contrôler
immédiatement l’accès et le payload, lancez un Job ponctuel puis lisez ses logs :

```bash
kubectl -n parralax-dns create job --from=cronjob/parralax-kubernetes-collector parralax-kubernetes-collector-check
kubectl -n parralax-dns logs job/parralax-kubernetes-collector-check
```

Le collecteur refuse par défaut de publier un inventaire sans hôte Ingress afin
de ne pas archiver accidentellement les données précédentes. Pour confirmer
volontairement un cluster vide, ajoutez `PARRALAX_ALLOW_EMPTY_INVENTORY=true`
au Secret, exécutez un Job, puis retirez cette variable.

## Exécution locale et dépannage

Le script accepte `--dry-run` et utilise le contexte `kubectl` courant. Il
nécessite `bash`, `kubectl`, `jq` et `curl` (sauf `curl` avec `--dry-run`).

```bash
PARRALAX_SOURCE=kubernetes-dev collectors/kubernetes/collect-kubernetes-dns.sh --dry-run
```

En cas de `Forbidden`, vérifiez le `ClusterRoleBinding` et :

```bash
kubectl auth can-i list ingresses.networking.k8s.io --all-namespaces \
  --as=system:serviceaccount:parralax-dns:parralax-kubernetes-collector
```
