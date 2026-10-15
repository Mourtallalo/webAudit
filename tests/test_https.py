"""
Tests du module HTTPS/TLS (remarques C07, E36, E35, E34), hors ligne.

La connexion TLS est simulée : https_checker._poignee_de_main est
remplacée par une fonction factice (monkeypatch), de même que la
vérification de la redirection HTTP -> HTTPS.
"""

import socket
import ssl

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import https_checker
import moteur

CERTIFICAT = {
    "notAfter": "Dec 12 12:00:00 2099 GMT",
    "issuer": ((("organizationName", "Let's Encrypt"),),),
    "subject": ((("commonName", "exemple.test"),),),
}

PRECISION_SANS_VERIFICATION = (
    " (lue lors d'une seconde connexion sans vérification du certificat, "
    "dans le seul but de connaître la version)")


def erreur_certificat(code, message="message OpenSSL"):
    e = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    e.verify_code = code
    e.verify_message = message
    return e


@pytest.fixture
def connexion(monkeypatch):
    """
    Simule la connexion TLS. comportement["verifiee"] et
    comportement["sans_verification"] : exception à lever, ou couple
    (version, certificat) à renvoyer. Les appels sont journalisés.
    """
    comportement = {"verifiee": ("TLSv1.3", CERTIFICAT), "sans_verification": ("TLSv1.3", {})}
    appels = []

    def fausse_poignee(hote, port, timeout, verifier=True):
        appels.append((hote, port, verifier))
        effet = comportement["verifiee" if verifier else "sans_verification"]
        if isinstance(effet, BaseException):
            raise effet
        return effet

    monkeypatch.setattr(https_checker, "_poignee_de_main", fausse_poignee)
    monkeypatch.setattr(https_checker, "verifier_redirection_https",
                        lambda hote, timeout=10, autoriser_local=False: {
                            "http_accessible": True, "redirige_vers_https": True,
                            "url_finale": "https://{}/".format(hote)})
    comportement["appels"] = appels
    return comportement


def observations(resultat):
    return {o["critere"]: (o["niveau"], o["message"]) for o in resultat["observations"]}


# ---------------------------------------------------------------------------
# C07 : port de l'URL
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url, port", [
    ("https://exemple.test", 443),
    ("https://exemple.test:8443/page", 8443),
    ("http://exemple.test:8080", 443),  # port du service HTTP, pas HTTPS
])
def test_port_de_l_url(connexion, url, port):
    resultat = https_checker.verifier_https(url)
    assert connexion["appels"] == [("exemple.test", port, True)]
    assert resultat["details"]["port_tls"] == port
    assert observations(resultat)["Disponibilité HTTPS"] == (
        "OK", "Le serveur répond en HTTPS (port {}).".format(port))


# ---------------------------------------------------------------------------
# Cas nominal et formulation de la version (E34)
# ---------------------------------------------------------------------------

def test_certificat_valide_version_negociee(connexion):
    obs = observations(https_checker.verifier_https("https://exemple.test"))
    assert obs["Disponibilité HTTPS"][0] == "OK"
    assert obs["Validité du certificat"][0] == "OK"
    assert obs["Version du protocole TLS"] == ("OK", "Version TLS négociée : TLSv1.3.")
    assert obs["Redirection HTTP vers HTTPS"][0] == "OK"


def test_aucun_message_ne_pretend_tester_toutes_les_versions(connexion):
    for version in ("TLSv1.2", "TLSv1.3"):
        connexion["verifiee"] = (version, CERTIFICAT)
        niveau, message = observations(
            https_checker.verifier_https("https://exemple.test"))["Version du protocole TLS"]
        assert message == "Version TLS négociée : {}.".format(version)
        for formulation in ("moderne", "sécurisée", "acceptable", "supporte", "toutes"):
            assert formulation not in message


# ---------------------------------------------------------------------------
# E36 : erreurs de certificat, classées selon verify_code
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, motif", [
    (10, "certificat expiré"),
    (18, "certificat auto-signé"),
    (19, "chaîne de certificats contenant un certificat auto-signé"),
    (20, "autorité de certification inconnue ou chaîne de certificats incomplète"),
    (21, "autorité de certification inconnue ou chaîne de certificats incomplète"),
    (62, "le nom d'hôte n'est pas couvert par le certificat"),
    (26, "certificat refusé (unsuitable certificate purpose)"),
])
def test_erreurs_de_certificat(connexion, code, motif):
    connexion["verifiee"] = erreur_certificat(code, "unsuitable certificate purpose")
    connexion["sans_verification"] = ("TLSv1.2", {})

    resultat = https_checker.verifier_https("https://exemple.test")
    obs = observations(resultat)

    assert resultat["statut"] == "succes"
    assert obs["Disponibilité HTTPS"] == ("OK", "Le serveur répond en HTTPS (port 443).")
    assert obs["Validité du certificat"] == (
        "CRITIQUE", "Certificat refusé : {} (code de vérification {}).".format(motif, code))
    # La version est lue par une seconde connexion, sans vérification.
    assert obs["Version du protocole TLS"] == (
        "OK", "Version TLS négociée : TLSv1.2" + PRECISION_SANS_VERIFICATION + ".")
    assert connexion["appels"] == [("exemple.test", 443, True), ("exemple.test", 443, False)]
    assert "Disponibilité HTTPS" in obs and obs["Disponibilité HTTPS"][0] != "CRITIQUE"


def test_certificat_refuse_version_illisible(connexion):
    connexion["verifiee"] = erreur_certificat(10)
    connexion["sans_verification"] = ConnectionResetError()
    obs = observations(https_checker.verifier_https("https://exemple.test"))
    assert obs["Validité du certificat"][0] == "CRITIQUE"
    assert "Version du protocole TLS" not in obs


# ---------------------------------------------------------------------------
# E35 : versions refusées
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("motif_openssl", ["TLSV1_ALERT_PROTOCOL_VERSION", "UNSUPPORTED_PROTOCOL"])
def test_version_de_protocole_refusee(connexion, motif_openssl):
    connexion["verifiee"] = ssl.SSLError(1, "[SSL: {}] erreur simulée (_ssl.c:1000)".format(motif_openssl))
    resultat = https_checker.verifier_https("https://exemple.test")
    assert resultat["statut"] == "succes"
    assert resultat["observations"] == [{
        "critere": "Version du protocole TLS",
        "niveau": "CRITIQUE",
        "message": "Le serveur refuse TLS 1.2 et 1.3 : il ne propose probablement que "
                   "TLS 1.0 ou 1.1 (non confirmé par l'outil).",
    }]


def test_service_non_tls_sur_le_port_https(connexion):
    """WRONG_VERSION_NUMBER : le port ne parle pas TLS (HTTP simple, par exemple)."""
    connexion["verifiee"] = ssl.SSLError(
        1, "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1000)")
    resultat = https_checker.verifier_https("https://exemple.test")
    obs = observations(resultat)
    assert resultat["details"]["certificat"]["etat"] == "https_absent"
    niveau, message = obs["Disponibilité HTTPS"]
    assert niveau == "CRITIQUE"
    assert message.startswith("Le site n'est PAS accessible en HTTPS (port 443).")
    assert "WRONG_VERSION_NUMBER" in message
    assert "Version du protocole TLS" not in obs


def test_autre_erreur_tls_https_non_disponible(connexion):
    connexion["verifiee"] = ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] échec simulé")
    niveau, message = observations(
        https_checker.verifier_https("https://exemple.test"))["Disponibilité HTTPS"]
    assert niveau == "CRITIQUE"
    assert "SSLV3_ALERT_HANDSHAKE_FAILURE" in message


# ---------------------------------------------------------------------------
# Cible injoignable : module en erreur, pas de CRITIQUE « HTTPS non disponible »
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exception, motif", [
    (socket.timeout("timed out"), "délai dépassé lors de la connexion TLS (port 443)"),
    (TimeoutError("handshake timed out"), "délai dépassé lors de la connexion TLS (port 443)"),
    (socket.gaierror(11001, "getaddrinfo failed"), "nom d'hôte introuvable"),
    (ConnectionRefusedError(), "connexion refusée sur le port 443"),
])
def test_cible_injoignable(connexion, exception, motif):
    connexion["verifiee"] = exception
    resultat = https_checker.verifier_https("https://exemple.test")
    assert resultat["statut"] == "erreur"
    assert resultat["observations"] == []
    assert resultat["message"] == "Contrôle TLS impossible (exemple.test:443) : {}.".format(motif)


def test_tls_injoignable_donne_un_audit_partiel(connexion, monkeypatch):
    """La page répond, mais pas le port TLS : audit partiel, aucune note."""
    connexion["verifiee"] = ConnectionRefusedError()

    def fausse_recuperation(url, timeout, autoriser_local=False):
        reponse = requests.Response()
        reponse.status_code = 200
        reponse.headers = CaseInsensitiveDict()
        reponse._content = b"<html></html>"
        reponse.encoding = "utf-8"
        return reponse, [url]

    monkeypatch.setattr(moteur, "recuperer_page", fausse_recuperation)
    resultat = moteur.lancer_scan("http://exemple.test:8080", autoriser_local=True)

    assert resultat["statut"] == "partiel"
    assert resultat["score"]["note"] is None
    assert resultat["score"]["modules_non_executes"] == ["HTTPS / TLS"]
    tls = resultat["modules"][1]
    assert tls["statut"] == "erreur" and tls["observations"] == []
    assert "HTTPS non disponible" not in resultat["rapport_texte"]
    assert "PAS accessible en HTTPS" not in resultat["rapport_texte"]
    assert "Hôte TLS       : exemple.test (port 443)" in resultat["rapport_texte"]
