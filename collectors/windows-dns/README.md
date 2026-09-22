# Collecteur Windows DNS autonome

Ce dossier peut être copié tel quel sur un serveur Windows DNS. Le collecteur
n'a besoin que de Windows PowerShell 5.1 et du module `DnsServer` fourni avec le
rôle DNS.

1. Copier `Sync-ParralaxDns.ps1` dans `C:\Program Files\Parralax-DNS`.
2. Copier `Sync-ParralaxDns.example.json` vers
   `C:\ProgramData\Parralax-DNS\Sync-ParralaxDns.json` et remplacer l'URL d'exemple.
3. Placer le jeton configuré côté API dans
   `C:\ProgramData\Parralax-DNS\collector.token` et limiter ses ACL au compte qui
   exécute le collecteur.
4. Lancer depuis une console administrateur :

```powershell
& 'C:\Program Files\Parralax-DNS\Sync-ParralaxDns.ps1' `
  -ConfigPath 'C:\ProgramData\Parralax-DNS\Sync-ParralaxDns.json' -Verbose
```

Le script envoie un `POST` HTTPS à
`/api/collectors/windows-dns/sync`. Il retourne l'objet de confirmation de
l'API en cas de succès et termine en erreur si la collecte ou l'envoi échoue.
La procédure d'installation détaillée et l'exemple de tâche planifiée se
trouvent dans le `README.md` à la racine du projet.
