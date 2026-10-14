"""
https_checker.py
================
Module de verification du protocole HTTPS et d'analyse du certificat TLS.

Ce module verifie :
  - si la cible est accessible en HTTPS
  - si une connexion HTTP est redirigee vers HTTPS
  - les caracteristiques du certificat TLS (validite, expiration, emetteur)
  - la version du protocole TLS negociee

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests


def _extraire_hote(url):
    """Extrait le nom d'hote d'une URL (ex. 'suncom.app' depuis 'https://suncom.app/page')."""
    analyse = urlparse(url)
    return analyse.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]


def verifier_redirection_https(hote, timeout=10):
    """
    Verifie si une connexion HTTP est automatiquement redirigee vers HTTPS.

    Retour
    ------
    dict avec 'http_accessible', 'redirige_vers_https' et 'url_finale'.
    """
    info = {"http_accessible": False, "redirige_vers_https": False, "url_finale": None}
    try:
        reponse = requests.get(
            "http://{}".format(hote),
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "WebAudit/1.0"},
        )
        info["http_accessible"] = True
        info["url_finale"] = reponse.url
        # Si l'URL finale commence par https, la redirection a eu lieu
        if reponse.url.lower().startswith("https://"):
            info["redirige_vers_https"] = True
    except requests.exceptions.RequestException:
        # Le site n'est pas accessible en HTTP simple (ce qui n'est pas un probleme)
        pass
    return info


def analyser_certificat(hote, port=443, timeout=10):
    """
    Etablit une connexion TLS et analyse le certificat du serveur.

    Retour
    ------
    dict contenant les informations du certificat, ou une erreur.
    """
    info_cert = {
        "https_actif": False,
        "version_tls": None,
        "certificat_valide": False,
        "date_expiration": None,
        "jours_avant_expiration": None,
        "emetteur": None,
        "sujet": None,
        "erreur": None,
    }

    contexte = ssl.create_default_context()

    try:
        # On ouvre une connexion socket classique...
        with socket.create_connection((hote, port), timeout=timeout) as connexion:
            # ...que l'on encapsule dans une couche TLS
            with contexte.wrap_socket(connexion, server_hostname=hote) as connexion_tls:
                info_cert["https_actif"] = True
                info_cert["version_tls"] = connexion_tls.version()
                certificat = connexion_tls.getpeercert()

                # Extraction de la date d'expiration
                date_exp_txt = certificat.get("notAfter")
                if date_exp_txt:
                    date_exp = datetime.strptime(date_exp_txt, "%b %d %H:%M:%S %Y %Z")
                    info_cert["date_expiration"] = date_exp.strftime("%Y-%m-%d")
                    delta = date_exp - datetime.now()
                    info_cert["jours_avant_expiration"] = delta.days
                    info_cert["certificat_valide"] = delta.days > 0

                # Extraction de l'emetteur (autorite de certification)
                emetteur = dict(x[0] for x in certificat.get("issuer", []))
                info_cert["emetteur"] = emetteur.get("organizationName", "Inconnu")

                # Extraction du sujet (a qui le certificat est delivre)
                sujet = dict(x[0] for x in certificat.get("subject", []))
                info_cert["sujet"] = sujet.get("commonName", "Inconnu")

    except ssl.SSLCertVerificationError as e:
        info_cert["erreur"] = "Certificat invalide : {}".format(e.verify_message if hasattr(e, "verify_message") else str(e))
    except ssl.SSLError as e:
        info_cert["erreur"] = "Erreur SSL/TLS : {}".format(e)
    except socket.timeout:
        info_cert["erreur"] = "Delai depasse lors de la connexion TLS."
    except socket.gaierror:
        info_cert["erreur"] = "Nom d'hote introuvable (echec de la resolution DNS)."
    except ConnectionRefusedError:
        info_cert["erreur"] = "Connexion refusee sur le port {}.".format(port)
    except Exception as e:
        info_cert["erreur"] = "Erreur inattendue : {}".format(e)

    return info_cert


def verifier_https(url, timeout=10):
    """
    Fonction principale du module : combine la verification de la redirection
    et l'analyse du certificat, puis produit des observations classifiees.

    Retour
    ------
    dict structure comme les autres modules du scanner.
    """
    hote = _extraire_hote(url)
    resultat = {
        "module": "HTTPS / TLS",
        "statut": "succes",
        "message": "",
        "observations": [],
        "details": {},
    }

    # --- Analyse du certificat TLS -----------------------------------------
    cert = analyser_certificat(hote, timeout=timeout)
    redirection = verifier_redirection_https(hote, timeout=timeout)
    resultat["details"] = {"certificat": cert, "redirection": redirection}

    # --- Observation 1 : HTTPS est-il actif ? ------------------------------
    if cert["https_actif"]:
        resultat["observations"].append({
            "critere": "Disponibilite HTTPS",
            "niveau": "OK",
            "message": "Le site est accessible en HTTPS.",
        })
    else:
        resultat["observations"].append({
            "critere": "Disponibilite HTTPS",
            "niveau": "CRITIQUE",
            "message": "Le site n'est PAS accessible en HTTPS. {}".format(cert["erreur"] or ""),
        })
        # Si HTTPS n'est pas actif, inutile de poursuivre l'analyse du certificat
        return resultat

    # --- Observation 2 : validite du certificat ----------------------------
    if cert["certificat_valide"]:
        jours = cert["jours_avant_expiration"]
        if jours < 30:
            resultat["observations"].append({
                "critere": "Validite du certificat",
                "niveau": "AVERTISSEMENT",
                "message": "Le certificat expire bientot ({} jours). Emetteur : {}.".format(jours, cert["emetteur"]),
            })
        else:
            resultat["observations"].append({
                "critere": "Validite du certificat",
                "niveau": "OK",
                "message": "Certificat valide (expire le {}, dans {} jours). Emetteur : {}.".format(
                    cert["date_expiration"], jours, cert["emetteur"]),
            })
    else:
        resultat["observations"].append({
            "critere": "Validite du certificat",
            "niveau": "CRITIQUE",
            "message": "Le certificat est expire ou invalide.",
        })

    # --- Observation 3 : version du protocole TLS --------------------------
    version = cert["version_tls"] or ""
    if version in ("TLSv1.3",):
        niveau_tls = "OK"
        msg_tls = "Version TLS moderne et securisee ({}).".format(version)
    elif version in ("TLSv1.2",):
        niveau_tls = "OK"
        msg_tls = "Version TLS acceptable ({}).".format(version)
    else:
        niveau_tls = "CRITIQUE"
        msg_tls = "Version TLS obsolete et vulnerable ({}). Mise a jour requise.".format(version or "inconnue")
    resultat["observations"].append({
        "critere": "Version du protocole TLS",
        "niveau": niveau_tls,
        "message": msg_tls,
    })

    # --- Observation 4 : redirection HTTP vers HTTPS -----------------------
    if redirection["http_accessible"]:
        if redirection["redirige_vers_https"]:
            resultat["observations"].append({
                "critere": "Redirection HTTP vers HTTPS",
                "niveau": "OK",
                "message": "Le trafic HTTP est correctement redirige vers HTTPS.",
            })
        else:
            resultat["observations"].append({
                "critere": "Redirection HTTP vers HTTPS",
                "niveau": "AVERTISSEMENT",
                "message": "Le site reste accessible en HTTP sans redirection vers HTTPS.",
            })

    return resultat


# ---------------------------------------------------------------------------
# Test unitaire du module
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    test = verifier_https("https://www.google.com")
    print(json.dumps(test, indent=2, ensure_ascii=False))
