# Journal des modifications

Version de référence : étiquette `v1.0-mesures-2026-10-14` (commit
`d7bfbee`, interface web des mesures du 14/10/2026 et ligne de commande de
juillet 2026). Version actuelle : `v2.0.1`.

## v2.0.1 — correctif (lot D)

| Identifiant | Ce qui a changé | Fichier(s) | Commit(s) |
|---|---|---|---|
| E36 | Un certificat refusé n'est plus une cible injoignable : type `certificat_refuse` dans `recuperer_page` ; la page est récupérée une seconde fois sans vérification (avertissement urllib3 neutralisé localement, redirections revalidées) ; mention dans le JSON (`remarque`) et le rapport texte ; audit complet, « Validité du certificat » CRITIQUE. | `reseau.py`, `moteur.py`, `reporter.py`, `README.md`, `tests/test_erreurs_tls.py` | commit de l'étiquette `v2.0.1` |
| E35 | Les autres erreurs TLS (version refusée, poignée de main impossible) donnent un audit partiel : en-têtes et CMS en erreur, module HTTPS exécuté (« Le serveur refuse TLS 1.2 et 1.3… »). | `reseau.py`, `moteur.py`, `tests/test_erreurs_tls.py` | commit de l'étiquette `v2.0.1` |
| E15 | `erreur_tls` retiré de `TYPES_INJOIGNABLE` : seuls un nom introuvable, une connexion refusée ou un délai dépassé rendent le scan impossible. | `reseau.py`, `moteur.py` | commit de l'étiquette `v2.0.1` |
| — | Tests : fixture automatique qui retire HTTP_PROXY, HTTPS_PROXY et ALL_PROXY (et leurs formes en minuscules) ; `c1.json` supprimé ; version de l'outil 2.0.1. | `tests/conftest.py`, `version.py` | commit de l'étiquette `v2.0.1` |

## v2.0.0

| Identifiant | Ce qui a changé | Fichier(s) | Commit(s) |
|---|---|---|---|
| C02 | Moteur d'analyse unique `lancer_scan`, utilisé par la ligne de commande et l'interface web ; copie divergente de juillet supprimée (conservée dans l'étiquette v1.0), rapports réels de juillet conservés dans `preuves/2026-07-06/`. | `moteur.py`, `scanner.py`, `app.py`, `preuves/2026-07-06/`, `tests/test_moteur.py` | `2e4507b`, `1670717` |
| E42 | La page est récupérée une seule fois par scan et transmise aux modules d'en-têtes et CMS. | `reseau.py`, `moteur.py`, `headers_analyzer.py`, `cms_detector.py` | `3aef17a` |
| E38 | Filtre anti-SSRF fondé sur les adresses résolues (IPv4 et IPv6) : refus si une seule adresse n'est pas publique. | `reseau.py`, `app.py`, `tests/test_reseau.py` | `3aef17a` |
| E39 | Redirections suivies à la main (5 au maximum), chaque nouvelle adresse revalidée par le filtre. | `reseau.py`, `https_checker.py` | `3aef17a` |
| E40 | Plus aucun test sur le début du nom d'hôte (`10.exemple.com` accepté s'il pointe vers une adresse publique) ; ancienne fonction `url_valide` supprimée. | `reseau.py`, `app.py` | `3aef17a` |
| E15 | Cible injoignable : scan « impossible », sans points ni note, avec un motif (JSON, rapport texte, interface, code de sortie 2). | `moteur.py`, `reporter.py`, `scanner.py`, `static/script.js`, `static/comparer.js` | `3aef17a` |
| C18 | URL saisie, URL finale après redirections et hôte du contrôle TLS dans le JSON et le rapport texte. | `moteur.py`, `reporter.py` | `3aef17a` |
| C07 | Le contrôle TLS utilise le port de l'URL https (443 par défaut). | `https_checker.py`, `moteur.py` | `a87ae27` |
| E36 | Erreurs de certificat classées selon `verify_code` (expiré, auto-signé, chaîne, autorité inconnue, nom non couvert, autre) ; version lue par une seconde connexion sans vérification. | `https_checker.py`, `tests/test_https.py` | `a87ae27` |
| E35 | Poignée de main refusée pour cause de version : « Version du protocole TLS » CRITIQUE (TLS 1.0/1.1 probable, non confirmé). | `https_checker.py` | `a87ae27` |
| E34 | Formulation « Version TLS négociée : … » ; README : Python 3.10 au minimum. | `https_checker.py`, `README.md` | `a87ae27` |
| E24 | X-Frame-Options satisfait aussi par la directive CSP `frame-ancestors`. | `headers_analyzer.py`, `tests/test_headers.py` | `64ea671` |
| E33 | Server et X-Powered-By pénalisés (INFO) seulement s'ils divulguent un numéro de version ; sinon OK. | `headers_analyzer.py` | `64ea671` |
| E32 | « En-tête présent (sa valeur n'est pas évaluée par l'outil) » ; aucune valeur classée comme dangereuse. | `headers_analyzer.py` | `64ea671` |
| C25 | Fiches d'en-têtes : avertissement « à adapter » (hébergement, vercel.json, services du site) ; `camera=(self)` dans Permissions-Policy. | `fiches.py`, `static/script.js`, `pdf_reporter.py` | `64ea671` |
| E27 | Version du CMS lue seulement dans la balise generator ou le `?ver=` des ressources du cœur sous `/wp-includes/`, avec source et confiance. | `cms_detector.py`, `tests/test_cms.py`, `tests/pages/` | `6e78e90` |
| E29 | Signatures propres à chaque CMS, deux indices de natures différentes ; signatures génériques seules supprimées. | `cms_detector.py`, `tests/pages/` | `6e78e90` |
| C05 | Version partielle (majeure seule) : INFO « impossible de conclure », sauf branche majeure absente des branches maintenues (CRITIQUE). | `cms_detector.py` | `6e78e90` |
| E28 | Référentiel daté et sourcé `versions_reference.json` (relevé du 14/10/2026), plus aucune version en dur ; mention dans les observations et les rapports. | `versions_reference.json`, `cms_detector.py`, `reporter.py` | `6e78e90` |
| E31 | Niveaux : AVERTISSEMENT si non à jour, CRITIQUE seulement pour une branche non maintenue d'après la source, OK si plus récente (« référentiel à mettre à jour ») ; aucune faille affirmée sans source. | `cms_detector.py`, `fiches.py` | `6e78e90` |
| C06 | Usage d'un CMS : observation OK (0 point) ; version masquée : OK « version non divulguée ». | `cms_detector.py` | `6e78e90` |
| E30 | Clé `"fichiers"` supprimée ; aucune requête supplémentaire. | `cms_detector.py` | `6e78e90` |
| C26 | Résumé texte avec « Informations » et « Points : x/100 » ; valeurs longues repliées au lieu d'être tronquées ; version de l'outil (`version.py`, 2.0.0) et date du référentiel dans le texte, le JSON et le PDF. | `reporter.py`, `version.py`, `moteur.py`, `pdf_reporter.py`, `app.py`, `tests/test_rapports.py` | `6af9ac3` |
| E64 | Accents rétablis dans les commentaires et docstrings, sans changement du code (AST identique). | `app.py`, `fiches.py`, `headers_analyzer.py`, `pdf_reporter.py`, `reporter.py` | `ac0b27a` |
| C16 | Mention légale : loi n°2008-11 du 25 janvier 2008 ; l'ancien numéro de loi, erroné, n'apparaît plus nulle part dans le projet. | `scanner.py` | `6af9ac3` |
| E26 | Case « Je certifie être autorisé » (audit et comparaison), contrôle serveur (`"autorisation": true`, sinon 400), option `--autorise` ou question (o/N), code de sortie 3 ; rien n'est enregistré. | `templates/index.html`, `templates/comparer.html`, `static/script.js`, `static/comparer.js`, `static/style.css`, `app.py`, `scanner.py`, `tests/test_autorisation.py` | `2260939` |
| C01 | Historique SQLite (`instance/historique.db`), route `GET /api/history`, courbe d'évolution du score en SVG. | `historique.py`, `app.py`, `templates/index.html`, `static/script.js`, `static/style.css`, `tests/test_historique.py` | `cf4bec1` |
| E43 | Vérification finale : suite de tests complète, égalité ligne de commande / interface web sur https://suncom.app (rapports dans `preuves/2026-10-14/`), README complet, ce journal, étiquette v2.0.0. | `preuves/2026-10-14/`, `README.md`, `CHANGELOG.md` | `d1844f1` et le commit de l'étiquette `v2.0.0` |
