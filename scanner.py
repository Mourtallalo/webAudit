#!/usr/bin/env python3
"""
scanner.py
==========
Ligne de commande de WebAudit.

Le scan est confié au moteur commun (moteur.lancer_scan), le même que
celui de l'interface web : les deux donnent les mêmes résultats.

USAGE :
    python scanner.py <URL>
    python scanner.py https://suncom.app
    python scanner.py https://suncom.app --json rapport.json --texte rapport.txt

Le fichier JSON a exactement la structure de la réponse de /api/scan.

AVERTISSEMENT ÉTHIQUE :
    Cet outil ne doit être utilisé que sur des systèmes pour lesquels vous
    disposez d'une autorisation explicite. L'audit de systèmes tiers sans
    autorisation est illégal (loi sénégalaise n° 2008-12 sur la cybercriminalité).

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import sys
import json
import argparse

from moteur import lancer_scan, normaliser_url
from reporter import enregistrer_rapport


def main(arguments_ligne=None):
    """Fonction principale : gestion des arguments et orchestration du scan."""
    parseur = argparse.ArgumentParser(
        description="WebAudit - Scanner de vulnérabilités web élémentaires.",
        epilog="Exemple : python scanner.py https://suncom.app --json rapport.json",
    )
    parseur.add_argument("url", help="URL de la cible à analyser (ex. https://suncom.app)")
    parseur.add_argument("--json", metavar="FICHIER", help="Enregistre le rapport JSON dans un fichier.")
    parseur.add_argument("--texte", metavar="FICHIER", help="Enregistre le rapport texte dans un fichier.")
    parseur.add_argument("--timeout", type=int, default=10, help="Délai d'attente en secondes (défaut : 10).")

    arguments = parseur.parse_args(arguments_ligne)

    # --- Bannière ----------------------------------------------------------
    print("=" * 70)
    print("   WebAudit 1.0 - Audit de sécurité web")
    print("   Mémoire L3 RT - Mourtalla LO - ESTM 2025-2026")
    print("=" * 70)
    print("[*] Cible : {}".format(normaliser_url(arguments.url)))
    print("[*] Analyse en cours (en-têtes HTTP, HTTPS/TLS, CMS)...")
    print("")

    # --- Exécution du scan -------------------------------------------------
    try:
        resultat = lancer_scan(arguments.url, timeout=arguments.timeout)
    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur.")
        sys.exit(1)

    # --- Affichage du rapport texte ----------------------------------------
    print(resultat["rapport_texte"])

    # --- Enregistrement des rapports si demandé ----------------------------
    if arguments.texte:
        enregistrer_rapport(resultat["rapport_texte"], arguments.texte)
        print("\n[+] Rapport texte enregistré dans : {}".format(arguments.texte))

    if arguments.json:
        enregistrer_rapport(json.dumps(resultat, indent=2, ensure_ascii=False), arguments.json)
        print("[+] Rapport JSON enregistré dans : {}".format(arguments.json))

    return resultat


if __name__ == "__main__":
    main()
