# WebAudit — Interface Web

Interface web pour le scanner de vulnérabilités WebAudit, développée dans le
cadre du mémoire de fin de Licence 3 Réseaux et Télécommunications (ESTM
2025-2026, Mourtalla LO).

Cette interface ne réimplémente aucune logique de scan : elle réutilise telles
quelles les modules Python déjà développés et testés (`headers_analyzer.py`,
`https_checker.py`, `cms_detector.py`, `reporter.py`) derrière un formulaire
web simple, construit avec Flask.

---

## Installation

### Prérequis
- Python 3.8 ou supérieur

### Étapes

```bash
# 1. Se placer dans le dossier du projet
cd webaudit_web

# 2. (Recommandé) créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

---

## Lancer l'application

```bash
python3 app.py
```

Puis ouvrir un navigateur à l'adresse : **http://127.0.0.1:5000**

Par défaut, le serveur écoute uniquement en local (`127.0.0.1`) et le mode
debug est désactivé — une bonne pratique de sécurité, particulièrement
pertinente pour un outil d'audit. Pour activer le rechargement automatique
pendant le développement :

```bash
FLASK_DEBUG=1 python3 app.py
```

---

## Utilisation

La ligne de commande et l'interface web sont dans le même dossier et
utilisent le même moteur d'analyse (`moteur.py`, fonction `lancer_scan`) :
pour une même cible, elles produisent le même score et les mêmes modules.

### Ligne de commande (`scanner.py`)

```bash
python scanner.py https://suncom.app
python scanner.py suncom.app --json rapport.json --texte rapport.txt
python scanner.py https://suncom.app --timeout 5
```

- `url` : la cible (avec ou sans `https://`, ajouté par défaut) ;
- `--json FICHIER` : enregistre le rapport JSON, avec exactement la même
  structure que la réponse de `/api/scan` (`url`, `date_scan`, `duree`,
  `score`, `modules`, `rapport_texte`) ;
- `--texte FICHIER` : enregistre le rapport texte affiché à l'écran ;
- `--timeout` : délai d'attente de chaque requête, en secondes (défaut : 10).

### Interface web (`app.py`)

1. Lancer `python app.py`, puis ouvrir **http://127.0.0.1:5000**
2. Saisir une URL dans le champ (ex. `suncom.app`, avec ou sans `https://`)
3. Cliquer sur **Auditer**
4. Le rapport s'affiche automatiquement : score global (A+ à F), puis le
   détail des observations pour chacun des trois modules (en-têtes HTTP,
   HTTPS/TLS, CMS)

Aucune donnée n'est enregistrée côté serveur : chaque scan est traité à la
volée et le résultat n'existe que dans la page affichée au navigateur.

Seule l'interface web filtre les cibles (refus des adresses locales et
privées, voir « Architecture technique ») ; la ligne de commande, lancée
par l'auditeur sur son propre poste, ne les filtre pas.

### Issue d'un scan

Le champ `statut` du JSON (et l'en-tête du rapport texte) indique :

- `complet` : les trois modules ont abouti ; points et note (A+ à F) ;
- `partiel` : la cible répond mais un module n'a pas abouti ; des points,
  sans note ;
- `impossible` : la page n'a pas pu être récupérée (nom de domaine
  introuvable, connexion refusée, délai dépassé, erreur TLS) ; ni points
  ni note, et le champ `motif` explique pourquoi. La ligne de commande se
  termine alors avec le code de sortie 2.

Le JSON et le rapport texte indiquent aussi l'URL saisie (`url`), l'URL
finale analysée après les redirections (`url_finale`, avec le parcours
complet dans `redirections`) et l'hôte interrogé par le contrôle TLS
(`hote_tls`).

### Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Les tests sont hors ligne : les modules d'analyse y sont remplacés par des
fonctions factices.

---

## Structure du projet

```
webaudit_web/
├── app.py                 # Application Flask (routes / et /api/scan)
├── scanner.py             # Ligne de commande
├── moteur.py              # Moteur d'analyse commun (lancer_scan)
├── reseau.py              # Filtre anti-SSRF et requête partagée
├── headers_analyzer.py    # Module d'analyse des en-têtes HTTP (existant)
├── https_checker.py       # Module de vérification HTTPS/TLS (existant)
├── cms_detector.py        # Module de détection du CMS (existant)
├── reporter.py            # Module de calcul du score (existant)
├── requirements.txt       # Dépendances Python
├── templates/
│   └── index.html         # Page unique de l'interface
└── static/
    ├── style.css           # Styles (thème "tampon d'audit officiel")
    └── script.js           # Logique cliente (formulaire, appel API, rendu)
```

---

## Architecture technique

L'application suit une architecture classique client-serveur :

- **Backend (`app.py`)** : expose une route `POST /api/scan` qui reçoit une
  URL en JSON, la filtre, puis appelle `moteur.lancer_scan`, qui exécute
  séquentiellement les trois modules d'analyse, calcule le score via
  `reporter.calculer_score`, et renvoie un
  rapport JSON allégé (sans les en-têtes bruts complets, non utilisés par
  l'affichage).
- **Frontend (`templates/index.html` + `static/`)** : une page unique en
  HTML/CSS/JavaScript vanilla (aucun framework), qui envoie une requête
  `fetch()` à `/api/scan` et construit dynamiquement le rapport dans le DOM.

Un filtre anti-SSRF (`reseau.valider_cible`) évite tout usage détourné de
l'interface web comme sonde du réseau interne du serveur. Il résout le nom
d'hôte (toutes les adresses IPv4 et IPv6) et refuse la cible si une seule
adresse n'est pas publique : privée, boucle locale, lien local (dont
`169.254.169.254`), multidiffusion, réservée, non spécifiée, IPv6 privée
(`fc00::/7`) ou lien local (`fe80::/10`), adresse IPv4 mappée en IPv6. Le
filtre porte sur les adresses, pas sur le nom : `10.exemple.com` est
accepté s'il pointe vers une adresse publique, `localtest.me` est refusé
parce qu'il pointe vers `127.0.0.1`.

La page est demandée une seule fois par scan (`reseau.recuperer_page`).
Les redirections sont suivies à la main (5 au maximum) et chaque nouvelle
adresse est revalidée par le même filtre.

---

## Limites connues

- **Rebinding DNS** : entre la validation DNS du filtre anti-SSRF et la
  connexion elle-même, un nom peut changer d'adresse (un serveur DNS
  malveillant peut répondre une adresse publique au filtre, puis une
  adresse interne au moment de la connexion). Le filtre réduit ce risque
  sans le supprimer.
- Le serveur de développement Flask (`app.run(debug=True)`) n'est pas conçu
  pour la production. Pour un déploiement réel, utiliser un serveur WSGI
  comme Gunicorn derrière un reverse proxy (Nginx).
- Le mode `debug=True` doit être désactivé avant tout déploiement public : il
  expose un débogueur interactif potentiellement dangereux.
- Chaque scan est synchrone : le navigateur attend la fin des trois modules
  avant d'afficher le rapport (généralement 1 à 5 secondes selon la cible).
