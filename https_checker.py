"""
https_checker.py
================
Module de vérification du protocole HTTPS et d'analyse du certificat TLS.

Ce module vérifie :
  - si la cible répond en HTTPS, sur le port de l'URL (443 par défaut, C07) ;
  - si une connexion HTTP est redirigée vers HTTPS ;
  - la validité du certificat TLS, avec le motif précis d'un refus (E36) ;
  - la version du protocole TLS NÉGOCIÉE lors de la connexion (E34).

L'outil ne teste pas une à une les versions acceptées par le serveur
(décision de l'auteur) : il lit la seule version négociée. Depuis
Python 3.10, le contexte TLS par défaut refuse les versions inférieures
à TLS 1.2 : un serveur limité à TLS 1.0 ou 1.1 fait donc échouer la
poignée de main, ce qui est signalé comme tel (E35).

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from reseau import recuperer_page, ErreurRecuperation


NOM_MODULE = "HTTPS / TLS"

PORT_HTTPS = 443

# Codes de vérification OpenSSL (verify_code) et motif affiché (E36).
MOTIFS_CERTIFICAT = {
    10: "certificat expiré",
    18: "certificat auto-signé",
    19: "chaîne de certificats contenant un certificat auto-signé",
    20: "autorité de certification inconnue ou chaîne de certificats incomplète",
    21: "autorité de certification inconnue ou chaîne de certificats incomplète",
    62: "le nom d'hôte n'est pas couvert par le certificat",
    64: "l'adresse IP n'est pas couverte par le certificat",
}

# Motifs OpenSSL d'une poignée de main refusée pour cause de version (E35).
# WRONG_VERSION_NUMBER n'en fait pas partie : il signale le plus souvent
# un service qui ne parle pas TLS du tout sur ce port (HTTP simple, par
# exemple), classé « https_absent ».
ERREURS_DE_VERSION = (
    "TLSV1_ALERT_PROTOCOL_VERSION",
    "UNSUPPORTED_PROTOCOL",
    "NO_PROTOCOLS_AVAILABLE",
    "VERSION_TOO_LOW",
)

MESSAGE_VERSION_REFUSEE = (
    "Le serveur refuse TLS 1.2 et 1.3 : il ne propose probablement que "
    "TLS 1.0 ou 1.1 (non confirmé par l'outil)"
)


def _cible_tls(url):
    """Hôte et port interrogés par le contrôle TLS (C07)."""
    analyse = urlparse(url)
    hote = analyse.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]
    # Le port de l'URL n'est repris que pour une URL https : pour une URL
    # http, c'est le port du service HTTP, pas celui du service HTTPS.
    port = analyse.port if analyse.scheme == "https" and analyse.port else PORT_HTTPS
    return hote, port


def verifier_redirection_https(hote, timeout=10, autoriser_local=False):
    """
    Vérifie si une connexion HTTP est automatiquement redirigée vers HTTPS.

    La requête passe par reseau.recuperer_page : chaque redirection est
    revalidée par le filtre anti-SSRF (E39).

    Retour
    ------
    dict avec 'http_accessible', 'redirige_vers_https' et 'url_finale'.
    """
    info = {"http_accessible": False, "redirige_vers_https": False, "url_finale": None}
    try:
        reponse, parcours = recuperer_page("http://{}".format(hote), timeout, autoriser_local)
        reponse.close()
        info["http_accessible"] = True
        info["url_finale"] = parcours[-1]
        # Si l'URL finale commence par https, la redirection a eu lieu
        if parcours[-1].lower().startswith("https://"):
            info["redirige_vers_https"] = True
    except ErreurRecuperation as e:
        # Le site n'est pas accessible en HTTP simple (ce qui n'est pas un problème)
        info["erreur"] = e.motif
    return info


def _poignee_de_main(hote, port, timeout, verifier=True):
    """
    Ouvre une connexion TLS et renvoie (version négociée, certificat).

    verifier=False désactive la vérification du certificat (CERT_NONE) :
    sert uniquement à lire la version négociée quand le certificat a été
    refusé ; le certificat renvoyé est alors vide.
    """
    contexte = ssl.create_default_context()
    if not verifier:
        contexte.check_hostname = False
        contexte.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hote, port), timeout=timeout) as connexion:
        with contexte.wrap_socket(connexion, server_hostname=hote) as connexion_tls:
            return connexion_tls.version(), connexion_tls.getpeercert()


def _erreur_de_version(erreur):
    """True si la poignée de main a échoué sur une version de protocole refusée."""
    texte = "{} {}".format(getattr(erreur, "reason", "") or "", erreur).upper()
    return any(motif in texte for motif in ERREURS_DE_VERSION)


def analyser_certificat(hote, port=PORT_HTTPS, timeout=10):
    """
    Établit une connexion TLS et analyse le certificat du serveur.

    Le champ « etat » résume l'issue :
      - "ok"                : poignée de main et certificat valides ;
      - "certificat_refuse" : le serveur répond en HTTPS, mais son
                              certificat est refusé (motif dans « erreur ») ;
      - "version_refusee"   : poignée de main refusée en TLS 1.2 et 1.3 ;
      - "https_absent"      : la connexion aboutit, mais pas en HTTPS, ou
                              elle est refusée sur le port HTTPS (aucun
                              service HTTPS, C28) ;
      - "injoignable"       : nom introuvable, délai dépassé.

    Retour
    ------
    dict contenant les informations du certificat.
    """
    info_cert = {
        "etat": None,
        "https_actif": False,
        "version_tls": None,
        "version_lue_sans_verification": False,
        "certificat_valide": False,
        "code_verification": None,
        "date_expiration": None,
        "jours_avant_expiration": None,
        "emetteur": None,
        "sujet": None,
        "erreur": None,
    }

    try:
        version, certificat = _poignee_de_main(hote, port, timeout)
    except ssl.SSLCertVerificationError as e:
        # Le serveur répond bien en HTTPS : c'est son certificat qui est refusé.
        code = getattr(e, "verify_code", None)
        motif = MOTIFS_CERTIFICAT.get(code)
        if motif is None:
            motif = "certificat refusé ({})".format(getattr(e, "verify_message", None) or e)
        info_cert.update(etat="certificat_refuse", https_actif=True,
                         code_verification=code, erreur=motif)
        # Seconde connexion, sans vérification, dans le seul but de lire
        # la version négociée.
        try:
            info_cert["version_tls"], _ = _poignee_de_main(hote, port, timeout, verifier=False)
            info_cert["version_lue_sans_verification"] = True
        except (OSError, ssl.SSLError):
            pass
        return info_cert
    except ssl.SSLError as e:
        if _erreur_de_version(e):
            info_cert.update(etat="version_refusee", erreur=MESSAGE_VERSION_REFUSEE)
        else:
            info_cert.update(etat="https_absent", erreur="Erreur SSL/TLS : {}".format(e))
        return info_cert
    except socket.gaierror:
        info_cert.update(etat="injoignable", erreur="nom d'hôte introuvable")
        return info_cert
    except (socket.timeout, TimeoutError):
        info_cert.update(etat="injoignable",
                         erreur="délai dépassé lors de la connexion TLS (port {})".format(port))
        return info_cert
    except ConnectionRefusedError:
        # C28 : ce contrôle ne s'exécute qu'une fois la page obtenue (sinon
        # le scan est « impossible ») : le serveur répond, mais refuse la
        # connexion sur le port HTTPS. C'est l'absence de HTTPS, pas une
        # cible injoignable.
        info_cert.update(etat="https_absent",
                         erreur="connexion refusée sur le port {} : aucun service HTTPS".format(port))
        return info_cert
    except ConnectionResetError:
        info_cert.update(etat="https_absent",
                         erreur="connexion interrompue par le serveur pendant la poignée de main TLS")
        return info_cert
    except OSError as e:
        info_cert.update(etat="injoignable", erreur="connexion impossible : {}".format(e))
        return info_cert

    info_cert.update(etat="ok", https_actif=True, version_tls=version)

    # Extraction de la date d'expiration
    date_exp_txt = certificat.get("notAfter")
    if date_exp_txt:
        date_exp = datetime.strptime(date_exp_txt, "%b %d %H:%M:%S %Y %Z")
        info_cert["date_expiration"] = date_exp.strftime("%Y-%m-%d")
        delta = date_exp - datetime.now()
        info_cert["jours_avant_expiration"] = delta.days
        info_cert["certificat_valide"] = delta.days > 0

    # Extraction de l'émetteur (autorité de certification)
    emetteur = dict(x[0] for x in certificat.get("issuer", []))
    info_cert["emetteur"] = emetteur.get("organizationName", "Inconnu")

    # Extraction du sujet (à qui le certificat est délivré)
    sujet = dict(x[0] for x in certificat.get("subject", []))
    info_cert["sujet"] = sujet.get("commonName", "Inconnu")

    return info_cert


def _observation_version(cert):
    """Observation « Version du protocole TLS » : la version négociée seulement (E34)."""
    version = cert["version_tls"]
    precision = ""
    if cert["version_lue_sans_verification"]:
        precision = (" (lue lors d'une seconde connexion sans vérification du certificat, "
                     "dans le seul but de connaître la version)")
    if version in ("TLSv1.3", "TLSv1.2"):
        niveau = "OK"
        message = "Version TLS négociée : {}{}.".format(version, precision)
    else:
        niveau = "CRITIQUE"
        message = "Version TLS négociée : {}{}. Version obsolète : mise à jour requise.".format(
            version or "inconnue", precision)
    return {"critere": "Version du protocole TLS", "niveau": niveau, "message": message}


def verifier_https(url, timeout=10, autoriser_local=False):
    """
    Fonction principale du module : combine la vérification de la redirection
    et l'analyse du certificat, puis produit des observations classifiées.

    Une cible injoignable (nom introuvable, délai dépassé) ne produit
    aucune observation : le module est marqué en
    erreur, et l'audit devient partiel.

    Retour
    ------
    dict structuré comme les autres modules du scanner.
    """
    hote, port = _cible_tls(url)
    resultat = {
        "module": NOM_MODULE,
        "statut": "succes",
        "message": "",
        "observations": [],
        "details": {"hote_tls": hote, "port_tls": port},
    }

    # --- Analyse du certificat TLS -----------------------------------------
    cert = analyser_certificat(hote, port=port, timeout=timeout)
    resultat["details"]["certificat"] = cert

    if cert["etat"] == "injoignable":
        resultat["statut"] = "erreur"
        resultat["message"] = "Contrôle TLS impossible ({}:{}) : {}.".format(hote, port, cert["erreur"])
        return resultat

    redirection = verifier_redirection_https(hote, timeout=timeout, autoriser_local=autoriser_local)
    resultat["details"]["redirection"] = redirection

    # --- Poignée de main refusée pour cause de version (E35) ----------------
    if cert["etat"] == "version_refusee":
        resultat["observations"].append({
            "critere": "Version du protocole TLS",
            "niveau": "CRITIQUE",
            "message": MESSAGE_VERSION_REFUSEE + ".",
        })
        return resultat

    # --- Observation 1 : HTTPS est-il actif ? ------------------------------
    if cert["https_actif"]:
        resultat["observations"].append({
            "critere": "Disponibilité HTTPS",
            "niveau": "OK",
            "message": "Le serveur répond en HTTPS (port {}).".format(port),
        })
    else:
        resultat["observations"].append({
            "critere": "Disponibilité HTTPS",
            "niveau": "CRITIQUE",
            "message": "Le site n'est PAS accessible en HTTPS (port {}). {}".format(port, cert["erreur"] or ""),
        })
        # Si HTTPS n'est pas actif, inutile de poursuivre l'analyse du certificat
        return resultat

    # --- Observation 2 : validité du certificat ----------------------------
    if cert["etat"] == "certificat_refuse":
        resultat["observations"].append({
            "critere": "Validité du certificat",
            "niveau": "CRITIQUE",
            "message": "Certificat refusé : {} (code de vérification {}).".format(
                cert["erreur"], cert["code_verification"]),
        })
    elif cert["certificat_valide"]:
        jours = cert["jours_avant_expiration"]
        if jours < 30:
            resultat["observations"].append({
                "critere": "Validité du certificat",
                "niveau": "AVERTISSEMENT",
                "message": "Le certificat expire bientôt ({} jours). Émetteur : {}.".format(jours, cert["emetteur"]),
            })
        else:
            resultat["observations"].append({
                "critere": "Validité du certificat",
                "niveau": "OK",
                "message": "Certificat valide (expire le {}, dans {} jours). Émetteur : {}.".format(
                    cert["date_expiration"], jours, cert["emetteur"]),
            })
    else:
        resultat["observations"].append({
            "critere": "Validité du certificat",
            "niveau": "CRITIQUE",
            "message": "Le certificat est expiré ou invalide.",
        })

    # --- Observation 3 : version du protocole TLS négociée -----------------
    if cert["version_tls"]:
        resultat["observations"].append(_observation_version(cert))

    # --- Observation 4 : redirection HTTP vers HTTPS -----------------------
    if redirection["http_accessible"]:
        if redirection["redirige_vers_https"]:
            resultat["observations"].append({
                "critere": "Redirection HTTP vers HTTPS",
                "niveau": "OK",
                "message": "Le trafic HTTP est correctement redirigé vers HTTPS.",
            })
        else:
            resultat["observations"].append({
                "critere": "Redirection HTTP vers HTTPS",
                "niveau": "AVERTISSEMENT",
                "message": "Le site reste accessible en HTTP sans redirection vers HTTPS.",
            })

    return resultat
