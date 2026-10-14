# WebAudit — Scanner de vulnérabilités web élémentaires

**Mémoire de fin de Licence 3 Réseaux et Télécommunications — ESTM 2025-2026**
**Auteur : Mourtalla LO — Encadreur : M. Malaw Ndiaye**

---

## Présentation

WebAudit est un outil d'audit de sécurité web **passif** développé en Python.
Il analyse une cible web selon trois axes et produit un rapport avec un score
de sécurité global (de A+ à F).

Les trois modules d'analyse :

1. **En-têtes HTTP de sécurité** — vérifie la présence et la configuration des
   en-têtes recommandés par l'OWASP (CSP, HSTS, X-Frame-Options, etc.).
2. **HTTPS / TLS** — vérifie la disponibilité de HTTPS, la validité du certificat
   et la version du protocole TLS.
3. **Détection de CMS** — identifie le CMS (WordPress, Joomla, Drupal, PrestaShop)
   et signale les versions obsolètes.

---

## Installation

### Prérequis
- Python 3.8 ou supérieur

### Étapes

```bash
# 1. Se placer dans le dossier du scanner
cd scanner

# 2. (Optionnel mais recommandé) créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate      # sous Linux/macOS
venv\Scripts\activate         # sous Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

---

## Utilisation

### Scan simple

```bash
python scanner.py https://suncom.app
```

### Scan avec enregistrement des rapports

```bash
python scanner.py https://suncom.app --json rapport.json --texte rapport.txt
```

### Options disponibles

| Option | Description |
|--------|-------------|
| `url` | (obligatoire) URL de la cible à analyser |
| `--json FICHIER` | Enregistre le rapport au format JSON |
| `--texte FICHIER` | Enregistre le rapport au format texte |
| `--timeout N` | Délai d'attente en secondes (défaut : 10) |

---

## Structure du projet

```
scanner/
├── scanner.py            # Point d'entrée principal
├── headers_analyzer.py   # Module d'analyse des en-têtes HTTP
├── https_checker.py      # Module de vérification HTTPS/TLS
├── cms_detector.py       # Module de détection du CMS
├── reporter.py           # Module de génération des rapports + scoring
├── requirements.txt      # Dépendances Python
└── README.md             # Ce fichier
```

Chaque module peut être testé individuellement :

```bash
python headers_analyzer.py
python https_checker.py
python cms_detector.py
```

---

## Avertissement éthique et légal

**Cet outil ne doit être utilisé que sur des systèmes pour lesquels vous
disposez d'une autorisation explicite du propriétaire.**

L'audit de systèmes tiers sans autorisation constitue une infraction pénale.
Au Sénégal, la loi n°2008-12 du 25 janvier 2008 sur la cybercriminalité
réprime les accès et le maintien frauduleux dans un système informatique.

WebAudit est un outil **passif** : il se limite à l'analyse des réponses
HTTP publiquement accessibles et ne réalise aucune exploitation de faille.

---

## Système de notation

Le score part de 100 points. Chaque observation retire des points :

| Niveau | Pénalité | Signification |
|--------|----------|---------------|
| CRITIQUE | −20 | Faille grave exposant à un risque immédiat |
| AVERTISSEMENT | −8 | Configuration sous-optimale |
| INFO | −2 | Information à surveiller |
| OK | 0 | Conforme aux bonnes pratiques |

| Note | Score | Interprétation |
|------|-------|----------------|
| A+ | 95-100 | Excellente sécurité |
| A | 85-94 | Très bonne sécurité |
| B | 70-84 | Bonne sécurité |
| C | 55-69 | Sécurité moyenne |
| D | 40-54 | Sécurité insuffisante |
| E | 20-39 | Sécurité faible |
| F | 0-19 | Sécurité critique |
