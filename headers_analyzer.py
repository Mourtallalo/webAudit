"""
headers_analyzer.py
===================
Module d'analyse des en-tetes HTTP de securite.

Ce module analyse la presence des en-tetes de securite recommandes par
l'OWASP dans une reponse HTTP deja obtenue (reseau.recuperer_page) : la
page n'est demandee qu'une seule fois pour tout le scan (E42).

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import re

NOM_MODULE = "En-tetes HTTP"

# Décision de l'auteur (E32) : la valeur des en-têtes n'est pas évaluée.
MESSAGE_PRESENT = "En-tête présent (sa valeur n'est pas évaluée par l'outil)."

# E24 : la directive CSP frame-ancestors protège elle aussi du détournement de clic.
MESSAGE_FRAME_ANCESTORS = "Protection assurée par la directive CSP frame-ancestors."

# E33 : un numéro de version, c'est-à-dire au moins un chiffre.
MOTIF_VERSION = re.compile(r"\d")

MESSAGE_SANS_VERSION = "En-tête présent, sans numéro de version : rien d'exploitable divulgué."
MESSAGE_AVEC_VERSION = "En-tête divulguant un numéro de version du logiciel."


# ---------------------------------------------------------------------------
# Definition des en-tetes de securite verifies et de leur criticite
# ---------------------------------------------------------------------------
# Chaque en-tete est associe a :
#   - une description de son role
#   - un niveau de criticite s'il est absent (CRITIQUE, AVERTISSEMENT, INFO)
#   - une valeur recommandee (a titre indicatif)
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "role": "Protège contre les attaques XSS en contrôlant les sources de contenu autorisées.",
        "criticite": "CRITIQUE",
        "recommandation": "default-src 'self'",
    },
    "Strict-Transport-Security": {
        "role": "Force le navigateur à utiliser HTTPS pour toutes les connexions futures.",
        "criticite": "CRITIQUE",
        "recommandation": "max-age=31536000; includeSubDomains",
    },
    "X-Frame-Options": {
        "role": "Protège contre le détournement de clic en interdisant l'affichage dans une iframe.",
        "criticite": "CRITIQUE",
        "recommandation": "DENY ou SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "role": "Empêche le navigateur de deviner le type MIME (protection anti MIME-sniffing).",
        "criticite": "AVERTISSEMENT",
        "recommandation": "nosniff",
    },
    "Referrer-Policy": {
        "role": "Contrôle les informations envoyées dans l'en-tête Referer.",
        "criticite": "AVERTISSEMENT",
        "recommandation": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "role": "Restreint l'accès aux API du navigateur (caméra, micro, géolocalisation).",
        "criticite": "INFO",
        "recommandation": "geolocation=(), microphone=(), camera=()",
    },
}


def analyser_headers_reponse(reponse):
    """
    Analyse les en-têtes HTTP de sécurité d'une réponse déjà obtenue.

    Paramètres
    ----------
    reponse : requests.Response
        La réponse finale renvoyée par reseau.recuperer_page.

    Retour
    ------
    dict
        Un dictionnaire structure contenant :
          - "statut"       : "succes" ou "erreur"
          - "message"      : message d'erreur eventuel
          - "observations" : liste des observations par en-tete
          - "headers_bruts": dictionnaire des en-tetes recus
    """
    resultat = {
        "module": NOM_MODULE,
        "statut": "succes",
        "message": "",
        "observations": [],
        "headers_bruts": {},
    }

    # On normalise les noms d'en-tetes recus en minuscules pour comparer
    headers_recus = {cle.lower(): valeur for cle, valeur in reponse.headers.items()}
    resultat["headers_bruts"] = dict(reponse.headers)

    csp = headers_recus.get("content-security-policy", "")

    # --- Verification de chaque en-tete de securite ------------------------
    for nom_header, infos in SECURITY_HEADERS.items():
        cle = nom_header.lower()
        if cle in headers_recus:
            # En-tete present : on enregistre une observation positive
            observation = {
                "header": nom_header,
                "present": True,
                "valeur": headers_recus[cle],
                "niveau": "OK",
                "role": infos["role"],
                "message": MESSAGE_PRESENT,
            }
        elif nom_header == "X-Frame-Options" and _contient_frame_ancestors(csp):
            # E24 : X-Frame-Options absent, mais la CSP protège déjà du
            # détournement de clic par sa directive frame-ancestors.
            observation = {
                "header": nom_header,
                "present": False,
                "valeur": None,
                "niveau": "OK",
                "role": infos["role"],
                "message": MESSAGE_FRAME_ANCESTORS,
            }
        else:
            # En-tete absent : on enregistre une observation selon la criticite
            observation = {
                "header": nom_header,
                "present": False,
                "valeur": None,
                "niveau": infos["criticite"],
                "role": infos["role"],
                "message": "En-tête absent. Recommandation : {}".format(infos["recommandation"]),
            }
        resultat["observations"].append(observation)

    # --- Detection d'en-tetes qui exposent trop d'informations -------------
    # Les en-têtes Server et X-Powered-By ne sont pénalisés (INFO) que s'ils
    # divulguent un numéro de version (E33) ; sinon, observation OK.
    for header_sensible in ["server", "x-powered-by"]:
        if header_sensible in headers_recus:
            valeur = headers_recus[header_sensible]
            avec_version = bool(MOTIF_VERSION.search(valeur))
            resultat["observations"].append({
                "header": header_sensible.title(),
                "present": True,
                "valeur": valeur,
                "niveau": "INFO" if avec_version else "OK",
                "role": "Révèle des informations sur la technologie du serveur.",
                "message": MESSAGE_AVEC_VERSION if avec_version else MESSAGE_SANS_VERSION,
            })

    return resultat


def _contient_frame_ancestors(csp):
    """True si la politique CSP contient la directive frame-ancestors (valeur non évaluée)."""
    return any(directive.strip().lower().split(" ")[0] == "frame-ancestors"
               for directive in csp.split(";"))
