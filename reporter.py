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
import textwrap
from datetime import datetime

from fiches import NOMS_MODULES
from cms_detector import MENTION_REFERENTIEL
from version import VERSION


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

    Principe : on ne note que ce qui a pu etre mesure.

    Un module qui n'a pas abouti — cible injoignable, delai depasse — ne
    produit aucune observation. Le penaliser d'un forfait reviendrait a
    noter une absence de mesure comme si c'etait un constat, et le
    forfait serait toujours arbitraire : dans la version precedente, un
    module d'en-tetes en echec coutait 20 points, alors que le meme
    module, s'il avait repondu sur un site mal configure, en aurait
    coute pres de 80. Un site injoignable obtenait donc une meilleure
    note qu'un site reellement audite et defaillant, ce qui rendait les
    scores incomparables entre eux.

    Le module en echec est donc exclu du calcul et declare comme tel.
    Mais exclure ne suffit pas : le score restant monterait alors
    mecaniquement, et une lettre posee dessus ferait passer un audit
    incomplet pour un bon resultat. La note est donc retiree — elle
    vaut None — des qu'un module manque. Une lettre est un jugement
    d'ensemble : on ne peut pas resumer ce qu'on n'a pas mesure. Les
    points restent fournis, comme mesure partielle a interpreter avec
    la liste des modules absents.

    Parametres
    ----------
    resultats : list
        Liste des dictionnaires retournes par chaque module.

    Retour
    ------
    dict avec :
      - 'points'   : score sur 100, calcule sur les modules aboutis
      - 'note'     : la lettre correspondante (A+ a F), ou None si
                     l'audit est partiel
      - 'decompte' : nombre d'observations par niveau de gravite
      - 'complet'  : False des qu'un module n'a pas abouti
      - 'modules_non_executes' : la liste de ces modules
    """
    score = 100
    decompte = {"CRITIQUE": 0, "AVERTISSEMENT": 0, "INFO": 0, "OK": 0}
    modules_non_executes = []

    for module in resultats:
        if module.get("statut") == "erreur":
            modules_non_executes.append(module.get("module", "Module inconnu"))
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

    complet = len(modules_non_executes) == 0

    return {
        "points": score,
        # Pas de lettre sur un audit incomplet : voir l'explication en
        # tete de fonction.
        "note": note if complet else None,
        "decompte": decompte,
        "complet": complet,
        "modules_non_executes": modules_non_executes,
    }


LARGEUR_RAPPORT = 70


def _entete_rapport(url, duree, date_scan, url_finale, hote_tls):
    """En-tête commun aux rapports texte : cible, URL finale (C18), date, durée."""
    largeur = LARGEUR_RAPPORT
    lignes = []
    lignes.append("=" * largeur)
    lignes.append("        RAPPORT D'AUDIT DE SÉCURITÉ WEB - WebAudit")
    lignes.append("=" * largeur)
    lignes.append("Outil          : WebAudit {}".format(VERSION))
    lignes.append("URL saisie     : {}".format(url))
    lignes.append("URL analysée   : {}".format(url_finale or "aucune (page non récupérée)"))
    lignes.append("Hôte TLS       : {}".format(hote_tls or "aucun (contrôle non effectué)"))
    moment = datetime.fromisoformat(date_scan) if date_scan else datetime.now()
    lignes.append("Date du scan   : {}".format(moment.strftime("%d/%m/%Y à %H:%M:%S")))
    lignes.append("Durée du scan  : {:.2f} secondes".format(duree))
    lignes.append("Versions CMS   : {}".format(MENTION_REFERENTIEL))
    lignes.append("")
    return lignes


def _pied_rapport():
    largeur = LARGEUR_RAPPORT
    return [
        "=" * largeur,
        "  Rapport généré par WebAudit {} - Outil d'audit académique".format(VERSION),
        "  Mémoire L3 RT - Mourtalla LO - ESTM 2025-2026",
        "=" * largeur,
    ]


def generer_rapport_impossible(url, motif, duree, date_scan=None, url_finale=None):
    """
    Rapport texte d'un scan impossible (E15) : la cible est injoignable.

    Aucun point ni aucune note : rien n'a pu être mesuré.
    """
    largeur = LARGEUR_RAPPORT
    lignes = _entete_rapport(url, duree, date_scan, url_finale, None)
    lignes.append("-" * largeur)
    lignes.append("  SCAN IMPOSSIBLE : {}".format(motif))
    lignes.append("-" * largeur)
    lignes.append("  La page n'a pas pu être récupérée : aucun contrôle n'a été")
    lignes.append("  effectué. Aucun point ni aucune note ne sont attribués.")
    lignes.append("  Vérifiez l'adresse saisie, puis relancez l'audit.")
    lignes.append("")
    lignes.extend(_pied_rapport())
    return "\n".join(lignes)


def generer_rapport_texte(url, resultats, score, duree, date_scan=None, url_finale=None, hote_tls=None):
    """
    Produit un rapport texte formate et lisible.

    Retour
    ------
    str : le rapport complet pret a etre affiche ou enregistre.
    """
    largeur = LARGEUR_RAPPORT
    lignes = _entete_rapport(url, duree, date_scan, url_finale, hote_tls)

    # --- Score global ------------------------------------------------------
    lignes.append("-" * largeur)
    if score.get("complet", True):
        lignes.append("  SCORE DE SÉCURITÉ GLOBAL : {}  ({}/100)".format(
            score["note"], score["points"]))
    else:
        lignes.append("  SCORE DE SÉCURITÉ GLOBAL : note non attribuée")
        lignes.append("  ({}/100 sur les seuls contrôles aboutis)".format(score["points"]))
    lignes.append("-" * largeur)
    d = score["decompte"]
    lignes.append("  Problèmes critiques   : {}".format(d["CRITIQUE"]))
    lignes.append("  Avertissements        : {}".format(d["AVERTISSEMENT"]))
    lignes.append("  Informations          : {}".format(d["INFO"]))
    lignes.append("  Points conformes      : {}".format(d["OK"]))
    # Le lecteur peut recalculer le score à partir de ce seul résumé (C26) :
    # 100 - 20 x critiques - 8 x avertissements - 2 x informations.
    lignes.append("  Points                : {}/100".format(score["points"]))

    # Un audit partiel ne doit pas se lire comme un quitus : on le dit
    # juste sous le score, pas en note de bas de page.
    if not score.get("complet", True):
        lignes.append("")
        lignes.append("  AUDIT PARTIEL : le score ne porte que sur les contrôles")
        lignes.append("  qui ont abouti. Module(s) sans réponse : {}.".format(
            ", ".join(score.get("modules_non_executes", []))))
        lignes.append("  Relancez l'audit avant de conclure.")
    lignes.append("")

    # --- Detail par module -------------------------------------------------
    for module in resultats:
        lignes.append("=" * largeur)
        # La cle "module" reste sans accent (elle sert d'identifiant) :
        # on affiche le libelle lisible correspondant.
        lignes.append("  MODULE : {}".format(
            NOMS_MODULES.get(module["module"], module["module"])))
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

            # Pour les en-têtes présents, on affiche la valeur complète,
            # repliée sur plusieurs lignes plutôt que tronquée (C26).
            if observation.get("present") and observation.get("valeur"):
                lignes.extend(textwrap.wrap(
                    str(observation["valeur"]), width=largeur,
                    initial_indent="      Valeur : ", subsequent_indent=" " * 15,
                    break_long_words=True, break_on_hyphens=False))
        lignes.append("")

    # --- Pied de page ------------------------------------------------------
    lignes.extend(_pied_rapport())

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
            "outil": "WebAudit {}".format(VERSION),
        },
        "score_global": score,
        "resultats_par_module": resultats,
    }
    return json.dumps(rapport, indent=2, ensure_ascii=False)


def enregistrer_rapport(contenu, chemin):
    """Enregistre un rapport dans un fichier."""
    with open(chemin, "w", encoding="utf-8") as fichier:
        fichier.write(contenu)
