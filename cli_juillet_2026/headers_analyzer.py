"""
headers_analyzer.py
===================
Module d'analyse des en-tetes HTTP de securite.

Ce module envoie une requete HTTP a une cible et analyse la presence
et la configuration des en-tetes de securite recommandes par l'OWASP.

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import requests


# ---------------------------------------------------------------------------
# Definition des en-tetes de securite verifies et de leur criticite
# ---------------------------------------------------------------------------
# Chaque en-tete est associe a :
#   - une description de son role
#   - un niveau de criticite s'il est absent (CRITIQUE, AVERTISSEMENT, INFO)
#   - une valeur recommandee (a titre indicatif)
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "role": "Protege contre les attaques XSS en controlant les sources de contenu autorisees.",
        "criticite": "CRITIQUE",
        "recommandation": "default-src 'self'",
    },
    "Strict-Transport-Security": {
        "role": "Force le navigateur a utiliser HTTPS pour toutes les connexions futures.",
        "criticite": "CRITIQUE",
        "recommandation": "max-age=31536000; includeSubDomains",
    },
    "X-Frame-Options": {
        "role": "Protege contre le clickjacking en interdisant l'affichage dans une iframe.",
        "criticite": "CRITIQUE",
        "recommandation": "DENY ou SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "role": "Empeche le navigateur de deviner le type MIME (protection anti MIME-sniffing).",
        "criticite": "AVERTISSEMENT",
        "recommandation": "nosniff",
    },
    "Referrer-Policy": {
        "role": "Controle les informations envoyees dans l'en-tete Referer.",
        "criticite": "AVERTISSEMENT",
        "recommandation": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "role": "Restreint l'acces aux API du navigateur (camera, micro, geolocalisation).",
        "criticite": "INFO",
        "recommandation": "geolocation=(), microphone=(), camera=()",
    },
}


def analyser_headers(url, timeout=10):
    """
    Analyse les en-tetes HTTP de securite d'une URL cible.

    Parametres
    ----------
    url : str
        L'URL complete de la cible (ex. "https://suncom.app").
    timeout : int
        Delai maximal d'attente de la reponse, en secondes.

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
        "module": "En-tetes HTTP",
        "statut": "succes",
        "message": "",
        "observations": [],
        "headers_bruts": {},
    }

    # --- Envoi de la requete HTTP ------------------------------------------
    try:
        reponse = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "WebAudit/1.0 (Audit de securite academique)"},
            allow_redirects=True,
        )
    except requests.exceptions.SSLError:
        resultat["statut"] = "erreur"
        resultat["message"] = "Erreur SSL : impossible d'etablir une connexion securisee."
        return resultat
    except requests.exceptions.ConnectionError:
        resultat["statut"] = "erreur"
        resultat["message"] = "Erreur de connexion : la cible est injoignable."
        return resultat
    except requests.exceptions.Timeout:
        resultat["statut"] = "erreur"
        resultat["message"] = "Delai d'attente depasse : la cible ne repond pas."
        return resultat
    except requests.exceptions.RequestException as e:
        resultat["statut"] = "erreur"
        resultat["message"] = "Erreur lors de la requete : {}".format(e)
        return resultat

    # On normalise les noms d'en-tetes recus en minuscules pour comparer
    headers_recus = {cle.lower(): valeur for cle, valeur in reponse.headers.items()}
    resultat["headers_bruts"] = dict(reponse.headers)

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
                "message": "En-tete present.",
            }
        else:
            # En-tete absent : on enregistre une observation selon la criticite
            observation = {
                "header": nom_header,
                "present": False,
                "valeur": None,
                "niveau": infos["criticite"],
                "role": infos["role"],
                "message": "En-tete absent. Recommandation : {}".format(infos["recommandation"]),
            }
        resultat["observations"].append(observation)

    # --- Detection d'en-tetes qui exposent trop d'informations -------------
    # Les en-tetes Server et X-Powered-By peuvent reveler des versions logicielles
    for header_sensible in ["server", "x-powered-by"]:
        if header_sensible in headers_recus:
            resultat["observations"].append({
                "header": header_sensible.title(),
                "present": True,
                "valeur": headers_recus[header_sensible],
                "niveau": "INFO",
                "role": "Revele des informations sur la technologie du serveur.",
                "message": "En-tete divulguant potentiellement des informations sensibles.",
            })

    return resultat


# ---------------------------------------------------------------------------
# Test unitaire du module (execute uniquement si on lance ce fichier seul)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    test = analyser_headers("https://www.google.com")
    print(json.dumps(test, indent=2, ensure_ascii=False))
