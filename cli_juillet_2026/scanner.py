#!/usr/bin/env python3
"""
scanner.py
==========
Point d'entree principal du scanner de vulnerabilites web WebAudit.

WebAudit est un outil d'audit passif qui analyse une cible web selon
trois axes :
  1. Les en-tetes HTTP de securite (module headers_analyzer)
  2. Le protocole HTTPS et le certificat TLS (module https_checker)
  3. Le systeme de gestion de contenu et sa version (module cms_detector)

Il produit un rapport structure avec un score de securite global.

USAGE :
    python scanner.py <URL>
    python scanner.py https://suncom.app
    python scanner.py https://suncom.app --json rapport.json --texte rapport.txt

AVERTISSEMENT ETHIQUE :
    Cet outil ne doit etre utilise que sur des systemes pour lesquels vous
    disposez d'une autorisation explicite. L'audit de systemes tiers sans
    autorisation est illegal (loi senegalaise n.2008-12 sur la cybercriminalite).

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import sys
import time
import argparse

# Import des modules du scanner
from headers_analyzer import analyser_headers
from https_checker import verifier_https
from cms_detector import detecter_cms
from reporter import (
    calculer_score,
    generer_rapport_texte,
    generer_rapport_json,
    enregistrer_rapport,
)


def normaliser_url(url):
    """
    S'assure que l'URL commence par un schema (http:// ou https://).
    Par defaut, on prefixe avec https://.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def lancer_scan(url, timeout=10):
    """
    Execute les trois modules d'analyse sur l'URL cible.

    Retour
    ------
    tuple (liste des resultats, duree du scan en secondes).
    """
    debut = time.time()
    resultats = []

    print("[*] Analyse des en-tetes HTTP de securite...")
    resultats.append(analyser_headers(url, timeout=timeout))

    print("[*] Verification du protocole HTTPS et du certificat TLS...")
    resultats.append(verifier_https(url, timeout=timeout))

    print("[*] Detection du CMS et de sa version...")
    resultats.append(detecter_cms(url, timeout=timeout))

    duree = time.time() - debut
    return resultats, duree


def main():
    """Fonction principale : gestion des arguments et orchestration du scan."""
    parseur = argparse.ArgumentParser(
        description="WebAudit - Scanner de vulnerabilites web elementaires.",
        epilog="Exemple : python scanner.py https://suncom.app --json rapport.json",
    )
    parseur.add_argument("url", help="URL de la cible a analyser (ex. https://suncom.app)")
    parseur.add_argument("--json", metavar="FICHIER", help="Enregistre le rapport JSON dans un fichier.")
    parseur.add_argument("--texte", metavar="FICHIER", help="Enregistre le rapport texte dans un fichier.")
    parseur.add_argument("--timeout", type=int, default=10, help="Delai d'attente en secondes (defaut : 10).")

    arguments = parseur.parse_args()
    url = normaliser_url(arguments.url)

    # --- Banniere ----------------------------------------------------------
    print("=" * 70)
    print("   WebAudit 1.0 - Audit de securite web")
    print("   Memoire L3 RT - Mourtalla LO - ESTM 2025-2026")
    print("=" * 70)
    print("[*] Cible : {}".format(url))
    print("")

    # --- Execution du scan -------------------------------------------------
    try:
        resultats, duree = lancer_scan(url, timeout=arguments.timeout)
    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur.")
        sys.exit(1)

    # --- Calcul du score ---------------------------------------------------
    score = calculer_score(resultats)

    # --- Generation et affichage du rapport texte --------------------------
    rapport_texte = generer_rapport_texte(url, resultats, score, duree)
    print("")
    print(rapport_texte)

    # --- Enregistrement des rapports si demande ----------------------------
    if arguments.texte:
        enregistrer_rapport(rapport_texte, arguments.texte)
        print("\n[+] Rapport texte enregistre dans : {}".format(arguments.texte))

    if arguments.json:
        rapport_json = generer_rapport_json(url, resultats, score, duree)
        enregistrer_rapport(rapport_json, arguments.json)
        print("[+] Rapport JSON enregistre dans : {}".format(arguments.json))


if __name__ == "__main__":
    main()
