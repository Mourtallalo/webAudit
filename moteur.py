"""
moteur.py
=========
Moteur d'analyse unique de WebAudit (remarque C02).

La ligne de commande (scanner.py) et l'interface web (app.py) appellent
toutes deux lancer_scan() : un même scan donne donc le même résultat,
quelle que soit la façon de le lancer.

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import time
from datetime import datetime

from headers_analyzer import analyser_headers
from https_checker import verifier_https
from cms_detector import detecter_cms
from reporter import calculer_score, generer_rapport_texte


def normaliser_url(url):
    """S'assure que l'URL commence par un schéma. Préfixe avec https:// par défaut."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def lancer_scan(url, timeout=10):
    """
    Exécute les trois modules d'analyse sur l'URL et produit le rapport.

    Aucun filtrage de la cible n'est fait ici : c'est à l'appelant de
    décider quelles URL il accepte (voir url_valide() dans app.py).

    Retour
    ------
    dict : {url, date_scan, duree, score, modules, rapport_texte}, soit
    exactement la réponse de /api/scan.
    """
    url = normaliser_url(url)

    debut = time.time()
    # Horodatage unique de l'audit, avec le fuseau local : il est repris
    # tel quel par l'interface, les exports .txt/.json et le rapport PDF.
    date_scan = datetime.now().astimezone().isoformat(timespec="seconds")

    resultats = [
        analyser_headers(url, timeout=timeout),
        verifier_https(url, timeout=timeout),
        detecter_cms(url, timeout=timeout),
    ]

    duree = round(time.time() - debut, 2)
    score = calculer_score(resultats)
    rapport_texte = generer_rapport_texte(url, resultats, score, duree, date_scan)

    # On retire les en-têtes bruts complets : ils ne sont pas affichés et
    # peuvent être volumineux. En revanche « details » est conservé : il est
    # compact, et porte les champs exploités par la comparaison multi-sites
    # (CMS détecté, disponibilité HTTPS) ainsi que par le rapport PDF.
    for module in resultats:
        module.pop("headers_bruts", None)

    return {
        "url": url,
        "date_scan": date_scan,
        "duree": duree,
        "score": score,
        "modules": resultats,
        "rapport_texte": rapport_texte,
    }
