"""
cms_detector.py
===============
Module de detection du systeme de gestion de contenu (CMS) et de sa version.

Ce module analyse le code source HTML d'une page ainsi que certains fichiers
caracteristiques afin d'identifier le CMS utilise (WordPress, Joomla, Drupal)
et de determiner si sa version est potentiellement obsolete.

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import re

import requests
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Signatures caracteristiques de chaque CMS
# ---------------------------------------------------------------------------
# Pour chaque CMS on definit :
#   - des motifs presents dans le code HTML (chemins, mots-cles)
#   - la derniere version stable connue (a actualiser periodiquement)
CMS_SIGNATURES = {
    "WordPress": {
        "motifs_html": ["/wp-content/", "/wp-includes/", "wp-json"],
        "fichiers": ["/readme.html", "/wp-login.php"],
        "derniere_version_stable": "6.5",
    },
    "Joomla": {
        "motifs_html": ["/media/jui/", "com_content", "/templates/"],
        "fichiers": ["/administrator/", "/language/en-GB/en-GB.xml"],
        "derniere_version_stable": "5.1",
    },
    "Drupal": {
        "motifs_html": ["/sites/default/files", "/core/misc/drupal.js", "Drupal.settings"],
        "fichiers": ["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
        "derniere_version_stable": "10.2",
    },
    "PrestaShop": {
        "motifs_html": ["/modules/", "prestashop", "/themes/"],
        "fichiers": ["/config/settings.inc.php"],
        "derniere_version_stable": "8.1",
    },
}


def _comparer_versions(version_detectee, version_stable):
    """
    Compare deux numeros de version (ex. '5.8' vs '6.5').

    Retour
    ------
    True si la version detectee est plus ancienne que la version stable.
    """
    def normaliser(v):
        # Transforme "6.5.2" en tuple (6, 5, 2) pour comparaison numerique
        return tuple(int(x) for x in re.findall(r"\d+", v))

    try:
        return normaliser(version_detectee) < normaliser(version_stable)
    except (ValueError, TypeError):
        return False


def detecter_version_wordpress(html):
    """Tente d'extraire la version de WordPress depuis la balise meta generator."""
    soup = BeautifulSoup(html, "html.parser")
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        correspondance = re.search(r"WordPress\s+([\d.]+)", generator["content"])
        if correspondance:
            return correspondance.group(1)
    # Recherche alternative dans le HTML brut
    correspondance = re.search(r"ver=([\d.]+)", html)
    if correspondance:
        return correspondance.group(1)
    return None


def detecter_version_generique(html, nom_cms):
    """Extrait une version depuis la balise meta generator pour un CMS donne."""
    soup = BeautifulSoup(html, "html.parser")
    generator = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if generator and generator.get("content"):
        correspondance = re.search(re.escape(nom_cms) + r"[!\s]+([\d.]+)", generator["content"], re.I)
        if correspondance:
            return correspondance.group(1)
    return None


def detecter_cms(url, timeout=10):
    """
    Fonction principale du module : identifie le CMS et evalue son obsolescence.

    Retour
    ------
    dict structure comme les autres modules du scanner.
    """
    resultat = {
        "module": "Detection CMS",
        "statut": "succes",
        "message": "",
        "observations": [],
        "details": {},
    }

    # --- Recuperation du code source de la page ----------------------------
    try:
        reponse = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "WebAudit/1.0"},
            allow_redirects=True,
        )
        html = reponse.text
    except requests.exceptions.RequestException as e:
        resultat["statut"] = "erreur"
        resultat["message"] = "Impossible de récupérer le contenu : {}".format(e)
        return resultat

    cms_detecte = None
    indices_trouves = []

    # --- Recherche des signatures dans le HTML -----------------------------
    for nom_cms, signature in CMS_SIGNATURES.items():
        for motif in signature["motifs_html"]:
            if motif.lower() in html.lower():
                cms_detecte = nom_cms
                indices_trouves.append(motif)
                break
        if cms_detecte:
            break

    # --- Aucun CMS detecte -------------------------------------------------
    if not cms_detecte:
        resultat["observations"].append({
            "critere": "Identification du CMS",
            "niveau": "OK",
            "message": "Aucun CMS standard détecté. Le site utilise probablement un développement sur mesure.",
        })
        resultat["details"] = {"cms": None, "version": None}
        return resultat

    # --- Un CMS a ete detecte : on cherche sa version ----------------------
    if cms_detecte == "WordPress":
        version = detecter_version_wordpress(html)
    else:
        version = detecter_version_generique(html, cms_detecte)

    signature = CMS_SIGNATURES[cms_detecte]
    version_stable = signature["derniere_version_stable"]

    resultat["details"] = {
        "cms": cms_detecte,
        "version": version,
        "version_stable": version_stable,
        "indices": indices_trouves,
    }

    resultat["observations"].append({
        "critere": "Identification du CMS",
        "niveau": "INFO",
        "message": "CMS détecté : {} (indices : {}).".format(cms_detecte, ", ".join(indices_trouves)),
    })

    # --- Evaluation de l'obsolescence de la version ------------------------
    if version:
        if _comparer_versions(version, version_stable):
            resultat["observations"].append({
                "critere": "Version du CMS",
                "niveau": "CRITIQUE",
                "message": "Version {} {} détectée, OBSOLÈTE (version stable : {}). "
                           "Des vulnérabilités connues peuvent exister. Mise à jour urgente.".format(
                               cms_detecte, version, version_stable),
            })
        else:
            resultat["observations"].append({
                "critere": "Version du CMS",
                "niveau": "OK",
                "message": "Version {} {} détectée, à jour ou récente (version stable : {}).".format(
                    cms_detecte, version, version_stable),
            })
    else:
        resultat["observations"].append({
            "critere": "Version du CMS",
            "niveau": "AVERTISSEMENT",
            "message": "CMS {} détecté mais version non identifiable. "
                       "La dissimulation de version est une bonne pratique, "
                       "mais vérifiez manuellement que le CMS est à jour.".format(cms_detecte),
        })

    return resultat


# ---------------------------------------------------------------------------
# Test unitaire du module
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    # WordPress.org est lui-meme sous WordPress : bon cas de test
    test = detecter_cms("https://wordpress.org/")
    print(json.dumps(test, indent=2, ensure_ascii=False))
