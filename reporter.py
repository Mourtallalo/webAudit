"""
reporter.py
===========
Module de génération des rapports de scan.

Ce module agrège les résultats des différents modules d'analyse, calcule
un score de sécurité global (de A+ à F) et produit deux formats de sortie :
  - un rapport texte lisible pour l'utilisateur
  - un rapport JSON structuré pour une exploitation automatisée

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import json
import textwrap
from datetime import datetime

from fiches import NOMS_MODULES
from cms_detector import MENTION_REFERENTIEL
from version import VERSION


# ---------------------------------------------------------------------------
# Pondération des niveaux de criticité pour le calcul du score
# ---------------------------------------------------------------------------
# Chaque observation retire un certain nombre de points selon sa gravité.
PENALITES = {
    "CRITIQUE": 20,
    "AVERTISSEMENT": 8,
    "INFO": 2,
    "OK": 0,
}

# Symboles utilisés dans le rapport texte
SYMBOLES = {
    "CRITIQUE": "[!]",   # problème grave
    "AVERTISSEMENT": "[~]",  # point d'attention
    "INFO": "[i]",       # information
    "OK": "[+]",         # conforme
}


def calculer_score(resultats):
    """
    Calcule un score de sécurité global à partir de l'ensemble des observations.

    Principe : on ne note que ce qui a pu être mesuré.

    Un module qui n'a pas abouti — cible injoignable, délai dépassé — ne
    produit aucune observation. Le pénaliser d'un forfait reviendrait à
    noter une absence de mesure comme si c'était un constat, et le
    forfait serait toujours arbitraire : dans la version précédente, un
    module d'en-têtes en échec coûtait 20 points, alors que le même
    module, s'il avait répondu sur un site mal configuré, en aurait
    coûté près de 80. Un site injoignable obtenait donc une meilleure
    note qu'un site réellement audité et défaillant, ce qui rendait les
    scores incomparables entre eux.

    Le module en échec est donc exclu du calcul et déclaré comme tel.
    Mais exclure ne suffit pas : le score restant monterait alors
    mécaniquement, et une lettre posée dessus ferait passer un audit
    incomplet pour un bon résultat. La note est donc retirée — elle
    vaut None — des qu'un module manque. Une lettre est un jugement
    d'ensemble : on ne peut pas résumer ce qu'on n'a pas mesuré. Les
    points restent fournis, comme mesure partielle à interpréter avec
    la liste des modules absents.

    Paramètres
    ----------
    resultats : list
        Liste des dictionnaires retournés par chaque module.

    Retour
    ------
    dict avec :
      - 'points'   : score sur 100, calculé sur les modules aboutis
      - 'note'     : la lettre correspondante (A+ à F), ou None si
                     l'audit est partiel
      - 'decompte' : nombre d'observations par niveau de gravité
      - 'complet'  : False dès qu'un module n'a pas abouti
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
        # tête de fonction.
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


def generer_rapport_texte(url, resultats, score, duree, date_scan=None, url_finale=None, hote_tls=None,
                          remarque=None):
    """
    Produit un rapport texte formaté et lisible.

    Retour
    ------
    str : le rapport complet prêt à être affiché ou enregistré.
    """
    largeur = LARGEUR_RAPPORT
    lignes = _entete_rapport(url, duree, date_scan, url_finale, hote_tls)
    # E36 : page récupérée sans vérification du certificat, par exemple.
    if remarque:
        lignes.extend(textwrap.wrap("Remarque : {}.".format(remarque), width=largeur,
                                    subsequent_indent="           "))
        lignes.append("")

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

    # --- Détail par module -------------------------------------------------
    for module in resultats:
        lignes.append("=" * largeur)
        # La clé "module" reste sans accent (elle sert d'identifiant) :
        # on affiche le libellé lisible correspondant.
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

            # Selon le module, la clé du libellé diffère
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
    str : le rapport au format JSON indenté.
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
