#!/usr/bin/env python3
"""
scanner.py
==========
Ligne de commande de WebAudit.

Le scan est confié au moteur commun (moteur.lancer_scan), le même que
celui de l'interface web : les deux donnent les mêmes résultats.

USAGE :
    python scanner.py <URL>
    python scanner.py https://suncom.app --autorise
    python scanner.py https://suncom.app --autorise --json rapport.json --texte rapport.txt

Sans --autorise, le programme demande « Êtes-vous autorisé à auditer
<hôte> ? (o/N) » ; une autre réponse que « o », ou une entrée non
interactive, l'arrête avec le code de sortie 3, sans rien scanner.

Le fichier JSON a exactement la structure de la réponse de /api/scan.

AVERTISSEMENT ÉTHIQUE :
    Cet outil ne doit être utilisé que sur des systèmes pour lesquels vous
    disposez d'une autorisation explicite. Auditer un système sans
    l'autorisation de son propriétaire peut engager la responsabilité pénale
    de son auteur (loi n°2008-11 du 25 janvier 2008 sur la cybercriminalité).

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import sys
import json
import argparse
from urllib.parse import urlparse

from moteur import lancer_scan, normaliser_url
from reporter import enregistrer_rapport
from version import VERSION

# Code de sortie quand la cible est injoignable (scan impossible).
CODE_SCAN_IMPOSSIBLE = 2

# Code de sortie quand l'autorisation d'auditer n'est pas confirmée (E26).
CODE_NON_AUTORISE = 3


def autorisation_confirmee(url):
    """
    Demande à l'utilisateur s'il est autorisé à auditer l'hôte.

    Une entrée non interactive (redirection, script) vaut refus : la
    question ne peut pas recevoir de réponse consciente.
    """
    if not sys.stdin or not sys.stdin.isatty():
        return False
    hote = urlparse(url).hostname or url
    try:
        reponse = input("Êtes-vous autorisé à auditer {} ? (o/N) ".format(hote))
    except EOFError:
        return False
    return reponse.strip().lower() == "o"


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
    parseur.add_argument("--autorise", action="store_true",
                         help="Certifie être autorisé à auditer la cible (sinon, la question est posée).")

    arguments = parseur.parse_args(arguments_ligne)

    # --- Autorisation (E26) ------------------------------------------------
    # Rien n'est enregistré au sujet de ce consentement.
    if not arguments.autorise and not autorisation_confirmee(normaliser_url(arguments.url)):
        print("[!] Scan annulé : autorisation non confirmée (option --autorise).", file=sys.stderr)
        sys.exit(CODE_NON_AUTORISE)

    # --- Bannière ----------------------------------------------------------
    print("=" * 70)
    print("   WebAudit {} - Audit de sécurité web".format(VERSION))
    print("   Mémoire L3 RT - Mourtalla LO - ESTM 2025-2026")
    print("=" * 70)
    print("[*] Cible : {}".format(normaliser_url(arguments.url)))
    print("[*] Analyse en cours (en-têtes HTTP, HTTPS/TLS, CMS)...")
    print("")

    # --- Exécution du scan -------------------------------------------------
    # La ligne de commande tourne sur le poste de l'auditeur : le filtre
    # anti-SSRF de l'interface web ne s'applique pas (autoriser_local=True).
    try:
        resultat = lancer_scan(arguments.url, timeout=arguments.timeout, autoriser_local=True)
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

    # Cible injoignable : scan impossible, code de sortie 2 (E15).
    if resultat["statut"] == "impossible":
        print("\n[!] Scan impossible : {}.".format(resultat["motif"]), file=sys.stderr)
        sys.exit(CODE_SCAN_IMPOSSIBLE)

    return resultat


if __name__ == "__main__":
    main()
