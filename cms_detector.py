"""
cms_detector.py
===============
Module de détection du système de gestion de contenu (CMS) et de sa version.

Ce module analyse le code source HTML de la page déjà obtenue par
reseau.recuperer_page (E42) afin d'identifier le CMS utilisé (WordPress,
Drupal, Joomla, PrestaShop) et de situer sa version par rapport au
référentiel daté et sourcé versions_reference.json (E28).

Principes :
  - une balise meta generator explicite suffit ; sinon, il faut au moins
    deux indices de natures différentes, propres au CMS (E29) ;
  - la version n'est lue qu'à des sources fiables : la balise generator
    ou, pour WordPress, le paramètre ?ver= des ressources du cœur sous
    /wp-includes/ (E27) ;
  - aucune requête supplémentaire : aucun fichier caractéristique n'est
    lu (E30, décision de l'auteur).

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import os
import re
import json
from collections import Counter
from datetime import date

from bs4 import BeautifulSoup


NOM_MODULE = "Detection CMS"

CHEMIN_REFERENTIEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "versions_reference.json")


def charger_referentiel(chemin=CHEMIN_REFERENTIEL):
    """Charge le référentiel des versions CMS (relevé manuel, daté et sourcé)."""
    with open(chemin, encoding="utf-8") as fichier:
        return json.load(fichier)


REFERENTIEL = charger_referentiel()

# « 2026-10-14 » -> « 14/10/2026 »
DATE_REFERENTIEL = date.fromisoformat(REFERENTIEL["date_releve"]).strftime("%d/%m/%Y")
MENTION_REFERENTIEL = "Référence des versions relevée le {}".format(DATE_REFERENTIEL)


# ---------------------------------------------------------------------------
# Signatures propres à chaque CMS (E29)
# ---------------------------------------------------------------------------
# Chaque signature est une liste de groupes : il faut au moins un indice
# dans CHAQUE groupe, et chaque groupe correspond à une nature d'indice
# différente. Un indice est un motif (expression régulière) recherché
# dans le HTML, ou ("entete", nom, motif) pour un en-tête HTTP.
SIGNATURES = {
    "WordPress": [
        [r"/wp-content/"],
        [r"/wp-includes/", r"https://api\.w\.org/"],
    ],
    "Drupal": [
        [("entete", "x-generator", r"drupal"), r"drupal-settings-json"],
        [r"/sites/default/files/", r"/core/misc/drupal\.js"],
    ],
    "Joomla": [
        [r"/media/system/js/", r"/media/jui/"],
        [r"option=com_", r"/components/com_"],
    ],
    "PrestaShop": [
        [r"\b(?:var|let|const)\s+prestashop\s*=", r"\bwindow\.prestashop\s*="],
        [r"/modules/ps_", r"/themes/[^\"'\s<>]+/assets/"],
    ],
}

# Nom du CMS tel qu'il apparaît dans la balise generator, suivi de sa version.
MOTIFS_GENERATOR = {
    "WordPress": r"WordPress",
    "Drupal": r"Drupal",
    "Joomla": r"Joomla!?",
    "PrestaShop": r"PrestaShop",
}

# Bibliothèques tierces embarquées sous /wp-includes/ : leur ?ver= est la
# version de la bibliothèque, pas celle de WordPress.
WP_INCLUDES_TIERS = ("/wp-includes/js/jquery/", "/wp-includes/js/dist/vendor/")

MOTIF_WP_INCLUDES_VER = re.compile(
    r"(/wp-includes/[^\"'\s<>?]+)\?(?:[^\"'\s<>]*?&(?:amp;)?)?ver=(\d+(?:\.\d+)+)(?=[&\"'\s<>]|$)",
    re.I)


def _version_en_tuple(version):
    """« 6.5.2 » -> (6, 5, 2)."""
    return tuple(int(x) for x in version.split("."))


def _indice_present(indice, html, entetes):
    if isinstance(indice, tuple):
        _, nom, motif = indice
        return bool(re.search(motif, entetes.get(nom, ""), re.I))
    return bool(re.search(indice, html, re.I))


def _libelle_indice(indice):
    if isinstance(indice, tuple):
        return "en-tête {}".format(indice[1])
    return indice.replace("\\", "")


def _lire_generator(html):
    """Contenu de la balise meta generator, ou None."""
    soup = BeautifulSoup(html, "html.parser")
    for balise in soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)}):
        if balise.get("content"):
            return balise["content"]
    return None


def _cms_du_generator(generator):
    """(nom du CMS, version ou None) d'après la balise generator, ou (None, None)."""
    if not generator:
        return None, None
    for nom_cms, motif in MOTIFS_GENERATOR.items():
        if re.search(r"\b" + motif, generator, re.I):
            correspondance = re.search(r"\b" + motif + r"\s+(\d+(?:\.\d+)*)", generator, re.I)
            return nom_cms, correspondance.group(1) if correspondance else None
    return None, None


def _cms_des_signatures(html, entetes):
    """(nom du CMS, indices trouvés) si une signature complète est présente."""
    for nom_cms, groupes in SIGNATURES.items():
        indices = []
        for groupe in groupes:
            trouves = [i for i in groupe if _indice_present(i, html, entetes)]
            if not trouves:
                break
            indices.append(_libelle_indice(trouves[0]))
        else:
            return nom_cms, indices
    return None, []


def _version_wp_includes(html):
    """
    Version de WordPress d'après le ?ver= des ressources du cœur sous /wp-includes/.

    Retour
    ------
    (version la plus fréquente, confiance) ou (None, None).
    """
    valeurs = [ver for chemin, ver in MOTIF_WP_INCLUDES_VER.findall(html)
               if not chemin.lower().startswith(WP_INCLUDES_TIERS)]
    if not valeurs:
        return None, None
    compte = Counter(valeurs)
    version = compte.most_common(1)[0][0]
    confiance = "moyenne" if len(compte) == 1 else "faible (valeurs divergentes : {})".format(
        ", ".join(sorted(compte)))
    return version, confiance


def _branche(version, branches):
    """Plus long préfixe de la version qui est une clé de « branches », ou None."""
    morceaux = version.split(".")
    for longueur in range(len(morceaux), 0, -1):
        prefixe = ".".join(morceaux[:longueur])
        if prefixe in branches:
            return prefixe
    return None


def evaluer_version(nom_cms, version, referentiel=None):
    """
    Situe une version par rapport au référentiel (C05, E31).

    Retour
    ------
    (niveau, message) ; le message cite la référence et sa source.
    """
    referentiel = referentiel or REFERENTIEL
    ref = referentiel["cms"].get(nom_cms)
    if ref is None:
        return "INFO", "{} {} : CMS absent du référentiel, impossible de conclure.".format(nom_cms, version)

    sources = " ; ".join(ref.get("sources", []))
    maintenues = ref.get("branches_maintenues")
    par_branche = maintenues or ref.get("dernieres_par_branche") or {}

    # --- Version partielle : seule la version majeure est connue (C05) ------
    if "." not in version:
        if maintenues and not any(b.split(".")[0] == version for b in maintenues):
            return "CRITIQUE", (
                "{} {} : aucune branche {} n'est maintenue d'après la source "
                "(branches maintenues : {} ; source : {}).".format(
                    nom_cms, version, version, ", ".join(maintenues), sources))
        return "INFO", "{} {} : version partielle : impossible de conclure.".format(nom_cms, version)

    branche = _branche(version, par_branche)

    # --- Branche non maintenue (CRITIQUE seulement si la liste existe) -------
    if maintenues and branche is None:
        profondeur = len(next(iter(maintenues)).split("."))
        branche_detectee = ".".join(version.split(".")[:profondeur])
        return "CRITIQUE", (
            "{} {} : la branche {} ne figure pas parmi les branches maintenues ({}) "
            "d'après la source ({}).".format(
                nom_cms, version, branche_detectee, ", ".join(maintenues), sources))

    reference = par_branche[branche] if branche else ref["derniere_version"]
    precision = "branche {}, ".format(branche) if branche else ""

    if _version_en_tuple(version) < _version_en_tuple(reference):
        return "AVERTISSEMENT", "{} {} : version non à jour (référence : {}{} ; source : {}).".format(
            nom_cms, version, precision, reference, sources)
    if _version_en_tuple(version) == _version_en_tuple(reference):
        return "OK", "{} {} : à jour (référence : {}{}).".format(nom_cms, version, precision, reference)
    return "OK", "{} {} : plus récente que la référence ({}{}) : référentiel à mettre à jour.".format(
        nom_cms, version, precision, reference)


def detecter_cms_reponse(reponse):
    """
    Fonction principale du module : identifie le CMS et situe sa version
    à partir d'une réponse déjà obtenue (requests.Response).

    Retour
    ------
    dict structuré comme les autres modules du scanner.
    """
    resultat = {
        "module": NOM_MODULE,
        "statut": "succes",
        "message": "",
        "observations": [],
        "details": {},
    }

    html = reponse.text
    entetes = {cle.lower(): valeur for cle, valeur in reponse.headers.items()}

    # --- Identification : generator explicite, sinon signature complète -----
    generator = _lire_generator(html)
    cms_detecte, version = _cms_du_generator(generator)
    if cms_detecte:
        indices = ["balise meta generator « {} »".format(generator)]
    else:
        cms_detecte, indices = _cms_des_signatures(html, entetes)

    # --- Aucun CMS détecté --------------------------------------------------
    if not cms_detecte:
        resultat["observations"].append({
            "critere": "Identification du CMS",
            "niveau": "OK",
            "message": "Aucun CMS standard détecté. Le site utilise probablement un développement sur mesure.",
        })
        resultat["details"] = {"cms": None, "version": None}
        return resultat

    # --- Version, depuis une source fiable uniquement (E27) -----------------
    source, confiance = None, None
    if version:
        source, confiance = "balise meta generator", "élevée"
    elif cms_detecte == "WordPress":
        version, confiance = _version_wp_includes(html)
        if version:
            source = "paramètre ?ver= des ressources du cœur sous /wp-includes/"

    reference = REFERENTIEL["cms"][cms_detecte]
    resultat["details"] = {
        "cms": cms_detecte,
        "version": version,
        "source_version": source,
        "confiance_version": confiance,
        "indices": indices,
        "version_reference": reference["derniere_version"],
        "date_referentiel": REFERENTIEL["date_releve"],
    }

    # Usage d'un CMS : constat neutre, aucun point retiré (C06).
    resultat["observations"].append({
        "critere": "Identification du CMS",
        "niveau": "OK",
        "message": "CMS détecté : {} (indices : {}).".format(cms_detecte, ", ".join(indices)),
    })

    # --- Situation de la version --------------------------------------------
    if version:
        niveau, message = evaluer_version(cms_detecte, version)
        message = "{} Version lue dans : {} (confiance {}). {}.".format(
            message, source, confiance, MENTION_REFERENTIEL)
    else:
        niveau = "OK"
        message = "Version non divulguée (bonne pratique) : actualité non vérifiable. {}.".format(
            MENTION_REFERENTIEL)

    resultat["observations"].append({
        "critere": "Version du CMS",
        "niveau": niveau,
        "message": message,
    })

    return resultat
