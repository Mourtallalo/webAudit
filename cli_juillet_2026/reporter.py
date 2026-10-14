"""
reporter.py
===========
Module de generation des rapports de scan.

Ce module agrege les resultats des differents modules d'analyse, calcule
un score de securite global (de A+ a F) et produit deux formats de sortie :
  - un rapport texte lisible pour l'utilisateur
  - un rapport JSON structure pour une exploitation automatisee

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import json
from datetime import datetime


# ---------------------------------------------------------------------------
# Ponderation des niveaux de criticite pour le calcul du score
# ---------------------------------------------------------------------------
# Chaque observation retire un certain nombre de points selon sa gravite.
PENALITES = {
    "CRITIQUE": 20,
    "AVERTISSEMENT": 8,
    "INFO": 2,
    "OK": 0,
}

# Symboles utilises dans le rapport texte
SYMBOLES = {
    "CRITIQUE": "[!]",   # probleme grave
    "AVERTISSEMENT": "[~]",  # point d'attention
    "INFO": "[i]",       # information
    "OK": "[+]",         # conforme
}


def calculer_score(resultats):
    """
    Calcule un score de securite global a partir de l'ensemble des observations.

    Parametres
    ----------
    resultats : list
        Liste des dictionnaires retournes par chaque module.

    Retour
    ------
    dict avec 'points', 'note' (lettre) et le decompte par niveau.
    """
    score = 100
    decompte = {"CRITIQUE": 0, "AVERTISSEMENT": 0, "INFO": 0, "OK": 0}

    for module in resultats:
        # Si un module entier est en erreur (cible injoignable), on penalise fortement
        if module.get("statut") == "erreur":
            score -= PENALITES["CRITIQUE"]
            decompte["CRITIQUE"] += 1
            continue
        for observation in module.get("observations", []):
            niveau = observation.get("niveau", "INFO")
            score -= PENALITES.get(niveau, 0)
            if niveau in decompte:
                decompte[niveau] += 1

    # Le score ne descend pas en dessous de 0
    score = max(0, score)

    # Attribution d'une note lettre en fonction du score
    if score >= 95:
        note = "A+"
    elif score >= 85:
        note = "A"
    elif score >= 70:
        note = "B"
    elif score >= 55:
        note = "C"
    elif score >= 40:
        note = "D"
    elif score >= 20:
        note = "E"
    else:
        note = "F"

    return {"points": score, "note": note, "decompte": decompte}


def generer_rapport_texte(url, resultats, score, duree):
    """
    Produit un rapport texte formate et lisible.

    Retour
    ------
    str : le rapport complet pret a etre affiche ou enregistre.
    """
    lignes = []
    largeur = 70

    lignes.append("=" * largeur)
    lignes.append("        RAPPORT D'AUDIT DE SECURITE WEB - WebAudit")
    lignes.append("=" * largeur)
    lignes.append("Cible analysee : {}".format(url))
    lignes.append("Date du scan   : {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    lignes.append("Duree du scan  : {:.2f} secondes".format(duree))
    lignes.append("")

    # --- Score global ------------------------------------------------------
    lignes.append("-" * largeur)
    lignes.append("  SCORE DE SECURITE GLOBAL : {}  ({}/100)".format(score["note"], score["points"]))
    lignes.append("-" * largeur)
    d = score["decompte"]
    lignes.append("  Problemes critiques   : {}".format(d["CRITIQUE"]))
    lignes.append("  Avertissements        : {}".format(d["AVERTISSEMENT"]))
    lignes.append("  Points conformes      : {}".format(d["OK"]))
    lignes.append("")

    # --- Detail par module -------------------------------------------------
    for module in resultats:
        lignes.append("=" * largeur)
        lignes.append("  MODULE : {}".format(module["module"]))
        lignes.append("=" * largeur)

        if module["statut"] == "erreur":
            lignes.append("  {} ERREUR : {}".format(SYMBOLES["CRITIQUE"], module["message"]))
            lignes.append("")
            continue

        for observation in module["observations"]:
            niveau = observation.get("niveau", "INFO")
            symbole = SYMBOLES.get(niveau, "[?]")

            # Selon le module, la cle du libelle differe
            libelle = observation.get("header") or observation.get("critere") or "Observation"
            message = observation.get("message", "")

            lignes.append("  {} {}".format(symbole, libelle))
            lignes.append("      {}".format(message))

            # Pour les en-tetes presents, on affiche la valeur
            if observation.get("present") and observation.get("valeur"):
                valeur = observation["valeur"]
                if len(valeur) > 60:
                    valeur = valeur[:60] + "..."
                lignes.append("      Valeur : {}".format(valeur))
        lignes.append("")

    # --- Pied de page ------------------------------------------------------
    lignes.append("=" * largeur)
    lignes.append("  Rapport genere par WebAudit - Outil d'audit academique")
    lignes.append("  Memoire L3 RT - Mourtalla LO - ESTM 2025-2026")
    lignes.append("=" * largeur)

    return "\n".join(lignes)


def generer_rapport_json(url, resultats, score, duree):
    """
    Produit un rapport JSON structure.

    Retour
    ------
    str : le rapport au format JSON indente.
    """
    rapport = {
        "metadonnees": {
            "cible": url,
            "date_scan": datetime.now().isoformat(),
            "duree_secondes": round(duree, 2),
            "outil": "WebAudit 1.0",
        },
        "score_global": score,
        "resultats_par_module": resultats,
    }
    return json.dumps(rapport, indent=2, ensure_ascii=False)


def enregistrer_rapport(contenu, chemin):
    """Enregistre un rapport dans un fichier."""
    with open(chemin, "w", encoding="utf-8") as fichier:
        fichier.write(contenu)
