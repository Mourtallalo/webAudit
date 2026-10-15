"""
Tests du lot D (remarques E36, E35, E15), hors ligne : un certificat
refusé ou une version TLS refusée ne rend pas le scan « impossible ».

La requête HTTP (requests.get dans reseau) et la connexion TLS du module
HTTPS (https_checker._poignee_de_main) sont simulées par monkeypatch.
"""

import ssl
import warnings

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import https_checker
import moteur
import reseau
from reseau import recuperer_page, ErreurRecuperation

URL = "https://expire.test"

MESSAGE_CERTIFICAT = ("HTTPSConnectionPool(host='expire.test', port=443): Max retries exceeded "
                      "(Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] "
                      "certificate verify failed: certificate has expired (_ssl.c:1000)')))")
MESSAGE_VERSION = ("HTTPSConnectionPool(host='expire.test', port=443): Max retries exceeded "
                   "(Caused by SSLError(SSLError(1, '[SSL: TLSV1_ALERT_PROTOCOL_VERSION] "
                   "tlsv1 alert protocol version (_ssl.c:1000)')))")


def page_ok(url):
    r = requests.Response()
    r.status_code = 200
    r.url = url
    r.headers = CaseInsensitiveDict({"X-Frame-Options": "DENY", "Server": "nginx/1.18.0"})
    r._content = b"<html><body>page</body></html>"
    r._content_consumed = True  # pas de flux réseau à fermer
    r.encoding = "utf-8"
    return r


def erreur_certificat_ssl(code, message):
    e = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    e.verify_code = code
    e.verify_message = message
    return e


@pytest.fixture
def cible(monkeypatch, dns):
    """
    Simule la cible : comportement["http"] est l'exception levée par
    requests.get quand le certificat est vérifié (None : page servie) ;
    comportement["tls"] celle levée par la connexion TLS du module HTTPS.
    Les appels à requests.get sont journalisés avec leur paramètre verify.
    """
    dns["expire.test"] = ["1.1.1.1"]
    comportement = {"http": None, "tls": None, "appels": []}

    def faux_get(url, timeout=None, headers=None, allow_redirects=True, verify=True):
        comportement["appels"].append((url, verify))
        if verify and comportement["http"] is not None:
            raise comportement["http"]
        # verify=False sans neutralisation : urllib3 avertirait ici.
        if not verify:
            warnings.warn("Unverified HTTPS request", reseau.urllib3.exceptions.InsecureRequestWarning)
        return page_ok(url)

    def fausse_poignee(hote, port, timeout, verifier=True):
        if verifier and comportement["tls"] is not None:
            raise comportement["tls"]
        return "TLSv1.3", {}

    monkeypatch.setattr(reseau.requests, "get", faux_get)
    monkeypatch.setattr(https_checker, "_poignee_de_main", fausse_poignee)
    monkeypatch.setattr(https_checker, "verifier_redirection_https",
                        lambda hote, timeout=10, autoriser_local=False: {
                            "http_accessible": False, "redirige_vers_https": False, "url_finale": None})
    return comportement


def observations(resultat, module):
    m = next(m for m in resultat["modules"] if m["module"] == module)
    return {(o.get("critere") or o.get("header")): (o["niveau"], o["message"]) for o in m["observations"]}


# ---------------------------------------------------------------------------
# reseau.recuperer_page : classification des erreurs TLS
# ---------------------------------------------------------------------------

def test_certificat_refuse_par_le_message(cible):
    cible["http"] = requests.exceptions.SSLError(MESSAGE_CERTIFICAT)
    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page(URL, timeout=5)
    assert erreur.value.type_erreur == "certificat_refuse"
    assert erreur.value.injoignable is False


def test_certificat_refuse_par_la_cause(cible):
    e = requests.exceptions.SSLError("erreur emballée")
    e.__cause__ = erreur_certificat_ssl(10, "certificate has expired")
    cible["http"] = e
    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page(URL, timeout=5)
    assert erreur.value.type_erreur == "certificat_refuse"


def test_autre_erreur_tls(cible):
    cible["http"] = requests.exceptions.SSLError(MESSAGE_VERSION)
    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page(URL, timeout=5)
    assert erreur.value.type_erreur == "erreur_tls"
    assert erreur.value.injoignable is False


def test_erreur_tls_n_est_plus_injoignable():
    assert reseau.TYPES_INJOIGNABLE == ("nom_introuvable", "connexion_refusee", "delai_depasse")


def test_sans_verification_sans_avertissement(cible):
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # tout avertissement ferait échouer le test
        reponse, parcours = recuperer_page(URL, timeout=5, verifier_certificat=False)
    assert reponse.status_code == 200
    assert cible["appels"] == [(URL, False)]


# ---------------------------------------------------------------------------
# moteur.lancer_scan
# ---------------------------------------------------------------------------

def test_certificat_expire_audit_complet(cible):
    cible["http"] = requests.exceptions.SSLError(MESSAGE_CERTIFICAT)
    cible["tls"] = erreur_certificat_ssl(10, "certificate has expired")

    resultat = moteur.lancer_scan(URL)

    assert resultat["statut"] == "complet"
    assert resultat["score"]["note"] is not None
    niveau, message = observations(resultat, "HTTPS / TLS")["Validité du certificat"]
    assert niveau == "CRITIQUE"
    assert "certificat expiré" in message
    # En-têtes analysés sur la page récupérée sans vérification.
    entetes = observations(resultat, "En-tetes HTTP")
    assert entetes["X-Frame-Options"][0] == "OK"
    assert entetes["Server"][0] == "INFO"
    # Une première requête vérifiée (refusée), puis une sans vérification.
    assert cible["appels"] == [(URL, True), (URL, False)]
    mention = "Page récupérée sans vérification du certificat, celui-ci ayant été refusé (voir le module HTTPS)"
    assert resultat["remarque"] == mention
    assert "sans vérification du certificat" in resultat["rapport_texte"]
    assert " ".join(resultat["rapport_texte"].split()).count(mention) == 1


def test_certificat_refuse_redirections_revalidees(cible, monkeypatch):
    """La seconde récupération applique les mêmes règles : redirection locale refusée."""
    cible["http"] = requests.exceptions.SSLError(MESSAGE_CERTIFICAT)

    def faux_get(url, timeout=None, headers=None, allow_redirects=True, verify=True):
        cible["appels"].append((url, verify))
        if verify:
            raise cible["http"]
        r = page_ok(url)
        r.status_code = 302
        r.headers["Location"] = "http://127.0.0.1/interne"
        return r

    monkeypatch.setattr(reseau.requests, "get", faux_get)
    resultat = moteur.lancer_scan(URL)
    assert resultat["statut"] == "partiel"
    assert "redirection refusée vers http://127.0.0.1/interne" in resultat["modules"][0]["message"]
    assert ("http://127.0.0.1/interne", False) not in cible["appels"]


def test_version_refusee_audit_partiel(cible):
    cible["http"] = requests.exceptions.SSLError(MESSAGE_VERSION)
    cible["tls"] = ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version")

    resultat = moteur.lancer_scan(URL)

    assert resultat["statut"] == "partiel"
    assert resultat["score"]["note"] is None
    assert isinstance(resultat["score"]["points"], int)
    assert observations(resultat, "HTTPS / TLS")["Version du protocole TLS"] == (
        "CRITIQUE", "Le serveur refuse TLS 1.2 et 1.3 : il ne propose probablement que "
                    "TLS 1.0 ou 1.1 (non confirmé par l'outil).")
    entetes, _, cms = resultat["modules"]
    assert entetes["statut"] == cms["statut"] == "erreur"
    assert entetes["message"].startswith("Page non récupérée : erreur TLS")
    assert resultat["remarque"] is None
    # Pas de seconde requête sans vérification pour une erreur de version.
    assert cible["appels"] == [(URL, True)]


def test_nom_introuvable_toujours_impossible():
    resultat = moteur.lancer_scan("https://inexistant.test")
    assert resultat["statut"] == "impossible"
    assert resultat["score"]["points"] is None and resultat["score"]["note"] is None


@pytest.mark.parametrize("exception, type_attendu", [
    (requests.exceptions.ConnectTimeout("délai"), "delai_depasse"),
    (requests.exceptions.ConnectionError("refusée"), "connexion_refusee"),
])
def test_injoignable_toujours_impossible(cible, exception, type_attendu):
    cible["http"] = exception
    resultat = moteur.lancer_scan(URL)
    assert resultat["statut"] == "impossible"
    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page(URL, timeout=5)
    assert erreur.value.type_erreur == type_attendu
