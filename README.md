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

1. Saisir une URL dans le champ (ex. `suncom.app`, avec ou sans `https://`)
2. Cliquer sur **Auditer**
3. Le rapport s'affiche automatiquement : score global (A+ à F), puis le
   détail des observations pour chacun des trois modules (en-têtes HTTP,
   HTTPS/TLS, CMS)

Aucune donnée n'est enregistrée côté serveur : chaque scan est traité à la
volée et le résultat n'existe que dans la page affichée au navigateur.

---

## Structure du projet

```
webaudit_web/
├── app.py                 # Application Flask (routes / et /api/scan)
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
  URL en JSON, exécute séquentiellement les trois modules d'analyse déjà
  développés, calcule le score via `reporter.calculer_score`, et renvoie un
  rapport JSON allégé (sans les en-têtes bruts complets, non utilisés par
  l'affichage).
- **Frontend (`templates/index.html` + `static/`)** : une page unique en
  HTML/CSS/JavaScript vanilla (aucun framework), qui envoie une requête
  `fetch()` à `/api/scan` et construit dynamiquement le rapport dans le DOM.

Une validation basique anti-SSRF rejette les cibles locales ou privées
(`localhost`, `127.0.0.1`, plages `192.168.x.x` et `10.x.x.x`) pour éviter
tout usage détourné de l'outil comme sonde du réseau interne du serveur.

---

## Limites connues

- Le serveur de développement Flask (`app.run(debug=True)`) n'est pas conçu
  pour la production. Pour un déploiement réel, utiliser un serveur WSGI
  comme Gunicorn derrière un reverse proxy (Nginx).
- Le mode `debug=True` doit être désactivé avant tout déploiement public : il
  expose un débogueur interactif potentiellement dangereux.
- Chaque scan est synchrone : le navigateur attend la fin des trois modules
  avant d'afficher le rapport (généralement 1 à 5 secondes selon la cible).
