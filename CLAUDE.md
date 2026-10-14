# Règles du projet WebAudit (mémoire L3 RT, ESTM 2025-2026, Mourtalla LO)

1. N'invente jamais un résultat : toute affirmation sur un test, un scan ou une mesure vient d'une commande réellement exécutée, dont tu montres la sortie.
2. Si tu n'as pas pu faire ou tester quelque chose, dis-le clairement dans le résumé final.
3. Ne change ni le barème (CRITIQUE 20, AVERTISSEMENT 8, INFO 2, OK 0) ni les seuils des notes (A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, E ≥ 20, sinon F) sans demande explicite.
4. N'ajoute aucune fonctionnalité hors du lot demandé. Décisions de l'auteur (14/10/2026) : pas de contrôle de la valeur des en-têtes, pas de test de chaque version TLS, pas de lecture de fichiers caractéristiques des CMS.
5. Vérifications en ligne : uniquement sur https://suncom.app (site de l'auteur) ou sur des serveurs locaux de test. Aucun autre site sans mon accord écrit dans la conversation.
6. Un seul moteur d'analyse : la ligne de commande (scanner.py) et l'interface web (app.py) utilisent les mêmes modules et donnent les mêmes résultats.
7. Code, messages et commentaires en français, avec les accents. Aucune nouvelle dépendance sans le signaler (pytest est déjà prévu).
8. Tests avec pytest, hors ligne (serveurs locaux, monkeypatch). Après chaque lot : python -m pytest -q, et colle la sortie réelle.
9. Un lot = un ou plusieurs commits, avec les identifiants des remarques dans le message (ex. « E15, C07 : … »). Jamais de rebase ni de push --force.
10. Les dossiers d'origine dans OneDrive (webaudit_web, WebAudit) sont en lecture seule.
11. Fin de chaque lot : résumé avec (a) les fichiers modifiés, (b) les commits, (c) la sortie réelle des tests, (d) ce qui n'a pas été fait ou reste à vérifier.
