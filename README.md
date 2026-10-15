# WebAudit 2.0.1

Scanner de vulnérabilités web élémentaires, développé dans le cadre du
mémoire de fin de Licence 3 Réseaux et Télécommunications (ESTM 2025-2026,
Mourtalla LO).

WebAudit réalise un audit **passif** d'un site selon trois axes :

1. les en-têtes HTTP de sécurité (`headers_analyzer.py`) ;
2. HTTPS et le certificat TLS (`https_checker.py`) ;
3. le CMS et sa version (`cms_detector.py`).

Il s'utilise par une **interface web** (`app.py`, Flask) ou en **ligne de
commande** (`scanner.py`). Les deux appellent le même moteur
(`moteur.lancer_scan`) : pour une même cible, ils donnent le même score et
les mêmes modules.

> N'auditez que des sites dont vous êtes le propriétaire ou pour lesquels
> vous avez un accord écrit. Auditer un système sans l'autorisation de son
> propriétaire peut engager la responsabilité pénale de son auteur (loi
> n°2008-11 du 25 janvier 2008 sur la cybercriminalité).

---

## Installation

**Prérequis : Python 3.10 au minimum.** Le contrôle TLS en dépend : depuis
Python 3.10, le contexte TLS par défaut refuse les versions inférieures à
TLS 1.2 (voir « Limites connues »).

### Avec uv

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv -r requirements.txt -r requirements-dev.txt
```

### Avec pip

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux / macOS
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest, pour les tests
```

Dépendances : Flask, requests, beautifulsoup4, reportlab (et pytest pour
les tests). L'historique utilise `sqlite3`, inclus dans Python.

---

## Utilisation

### Interface web

```bash
python app.py
```

Puis ouvrir **http://127.0.0.1:5000**.

1. Saisir l'adresse du site (ex. `suncom.app`, avec ou sans `https://`).
2. Cocher la case **« Je certifie être autorisé à auditer ce site (j'en
   suis le propriétaire ou j'ai son accord écrit). »** Le bouton
   **Auditer** reste désactivé tant qu'elle n'est pas cochée.
3. Le rapport s'affiche : note (A+ à F), points sur 100, décompte par
   niveau, détail des trois modules avec les correctifs, puis l'évolution
   du score pour cet hôte.
4. Téléchargements : rapport PDF, rapport texte (.txt), données (.json).

La page **Comparer** audite plusieurs sites à la suite (30 au maximum),
avec une case équivalente : « Je certifie être autorisé à auditer chacun
de ces sites ».

Le serveur écoute uniquement en local (`127.0.0.1`) et le mode debug est
désactivé par défaut (`FLASK_DEBUG=1` pour l'activer en développement).

### Ligne de commande

```bash
python scanner.py https://suncom.app --autorise
python scanner.py suncom.app --autorise --json rapport.json --texte rapport.txt
python scanner.py https://suncom.app --autorise --timeout 5
```

- `url` : la cible (`https://` est ajouté si le schéma manque) ;
- `--autorise` : certifie être autorisé à auditer la cible. Sans cette
  option, le programme demande « Êtes-vous autorisé à auditer <hôte> ?
  (o/N) » ; toute autre réponse que « o », ou une entrée non interactive
  (script, redirection), l'arrête **sans rien scanner** ;
- `--json FICHIER` : rapport JSON, de même structure que la réponse de
  `/api/scan` ;
- `--texte FICHIER` : le rapport texte affiché à l'écran ;
- `--timeout` : délai d'attente de chaque requête, en secondes (défaut : 10).

Codes de sortie : `0` scan effectué, `2` scan impossible (cible
injoignable), `3` autorisation non confirmée.

La ligne de commande tourne sur le poste de l'auditeur : elle n'applique
pas le filtre anti-SSRF de l'interface web et n'écrit rien dans
l'historique.

---

## Case d'autorisation

La confirmation est exigée à trois niveaux : la case de l'interface, le
serveur (`/api/scan` refuse avec le code 400 et le message « Confirmez que
vous êtes autorisé à auditer ce site. » si le corps ne contient pas
`"autorisation": true`), et la ligne de commande (`--autorise` ou réponse
« o »). **Rien n'est enregistré au sujet de ce consentement.**

---

## Score et rapports

Chaque observation retire des points selon son niveau : **CRITIQUE 20,
AVERTISSEMENT 8, INFO 2, OK 0**. Note : **A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55,
D ≥ 40, E ≥ 20, sinon F**. Le résumé du rapport texte (critiques,
avertissements, informations, conformes, points) permet de recalculer le
score.

Issue d'un scan (champ `statut`) :

- `complet` : les trois modules ont abouti ; points et note ;
- `partiel` : la cible répond mais un module n'a pas abouti ; des points,
  **sans note** ;
- `impossible` : la cible est injoignable (nom de domaine introuvable,
  connexion refusée, délai dépassé) ; ni points ni note, et le champ
  `motif` explique pourquoi.

### Certificat invalide ou version TLS refusée

Une erreur TLS ne rend jamais le scan « impossible » : la cible répond, et
le module HTTPS sait classer le problème.

- **Certificat refusé** (expiré, auto-signé, autorité inconnue, nom non
  couvert…) : la page est récupérée une seconde fois **sans vérification
  du certificat**, avec les mêmes règles (redirections revalidées par le
  filtre), pour analyser les en-têtes et le CMS. Le JSON (champ
  `remarque`) et le rapport texte indiquent : « Page récupérée sans
  vérification du certificat, celui-ci ayant été refusé (voir le module
  HTTPS) ». Le module HTTPS donne « Validité du certificat » CRITIQUE avec
  le motif précis. L'audit est **complet** (points et note).
- **Autre erreur TLS** (version refusée, poignée de main impossible) :
  audit **partiel**. Les modules d'en-têtes et CMS sont en erreur (« Page
  non récupérée : … ») ; le module HTTPS s'exécute et produit son
  observation (par exemple « Le serveur refuse TLS 1.2 et 1.3… »). Des
  points, sans note.

Le JSON contient : `url` (URL saisie), `url_finale` (après les
redirections, parcours complet dans `redirections`), `hote_tls`, `statut`,
`motif`, `remarque`, `version_outil`, `date_referentiel_cms`, `date_scan`, `duree`,
`score`, `modules`, `rapport_texte`. Le rapport texte et le PDF indiquent
la version de WebAudit, l'URL finale et la date du référentiel des
versions CMS.

---

## Historique des scans

L'interface web conserve un historique **sur l'ordinateur qui exécute
`app.py`**, dans la base SQLite `instance/historique.db` (dossier ignoré
par Git). Pour chaque scan abouti : l'hôte, l'URL saisie, la date du scan,
la note, les points, le décompte des quatre niveaux, l'indicateur « audit
complet » et la version de l'outil. Rien d'autre (ni le détail des
observations, ni la confirmation d'autorisation).

- Un scan « impossible » n'est pas enregistré ; la ligne de commande
  n'écrit rien.
- `GET /api/history?url=…` renvoie `{hote, scans}`, du plus ancien au plus
  récent ; l'interface en trace la courbe (« Évolution du score pour cet
  hôte ») dès deux scans.
- **Pour tout effacer** : supprimer le fichier `instance/historique.db`.

---

## Tests

```bash
python -m pytest -q
```

Les tests sont **hors ligne** : résolution DNS factice (`tests/conftest.py`),
serveur HTTP local dans un thread, connexion TLS simulée, pages HTML de
test (`tests/pages/`), base d'historique temporaire. Aucun test ne
contacte un site réel.

---

## Structure du projet

```
webaudit/
├── app.py                  # Interface web Flask : /, /comparer, /api/scan,
│                           #   /api/history, /api/rapport-pdf
├── scanner.py              # Ligne de commande
├── moteur.py               # Moteur d'analyse commun (lancer_scan)
├── reseau.py               # Filtre anti-SSRF et requête partagée
├── headers_analyzer.py     # En-têtes HTTP de sécurité
├── https_checker.py        # HTTPS et certificat TLS
├── cms_detector.py         # Détection du CMS et de sa version
├── versions_reference.json # Référentiel daté des versions CMS
├── reporter.py             # Score et rapport texte
├── pdf_reporter.py         # Rapport PDF
├── fiches.py               # Explications et correctifs
├── historique.py           # Historique SQLite
├── version.py              # Version de WebAudit
├── templates/, static/     # Pages, styles et scripts de l'interface
├── preuves/                # Rapports réels conservés (juillet et octobre 2026)
└── tests/                  # Tests pytest hors ligne
```

---

## Architecture et sécurité de l'outil

- **Filtre anti-SSRF** (`reseau.valider_cible`, interface web) : le nom
  d'hôte est résolu (toutes les adresses IPv4 et IPv6) et la cible est
  refusée si une seule adresse n'est pas publique (privée, boucle locale,
  lien local dont `169.254.169.254`, multidiffusion, réservée, non
  spécifiée, `fc00::/7`, `fe80::/10`, IPv4 mappée en IPv6). Le filtre porte
  sur les adresses, pas sur le nom : `10.exemple.com` est accepté s'il
  pointe vers une adresse publique, `localtest.me` est refusé.
- **Une seule requête** pour la page analysée (`reseau.recuperer_page`) ;
  les redirections sont suivies à la main (5 au maximum) et chaque
  nouvelle adresse est revalidée.
- **Contrôle TLS** sur le port de l'URL (443 par défaut) ; les erreurs de
  certificat sont classées (expiré, auto-signé, autorité inconnue, nom non
  couvert…).
- **CMS** : signatures à deux indices, version lue seulement à des sources
  fiables, comparée au référentiel `versions_reference.json`.

---

## Limites connues

- **En-têtes : présence seulement.** L'outil vérifie qu'un en-tête est
  présent, pas que sa valeur est sûre (décision de l'auteur).
- **TLS : version négociée seulement.** L'outil lit la version obtenue lors
  de la connexion et ne teste pas une à une les versions acceptées par le
  serveur. Un serveur limité à TLS 1.0 ou 1.1 est signalé par l'échec de la
  poignée de main, sans confirmation de la version exacte.
- **CMS : aucune lecture de fichiers caractéristiques** (readme.html,
  CHANGELOG.txt…). Seule la page d'accueil est analysée.
- **Rebinding DNS** : entre la validation DNS du filtre anti-SSRF et la
  connexion, un nom peut changer d'adresse. Le filtre réduit ce risque
  sans le supprimer.
- **Référentiel des versions CMS à mettre à jour** :
  `versions_reference.json` est un relevé manuel (14/10/2026) ; il doit
  être actualisé avant chaque campagne de mesures. Une version plus
  récente que la référence est signalée « référentiel à mettre à jour ».
- Le serveur de développement Flask n'est pas conçu pour la production
  (utiliser un serveur WSGI derrière un reverse proxy pour un déploiement).
- Chaque scan est synchrone (généralement 1 à 5 secondes).
