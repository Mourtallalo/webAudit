"""
Tests du module d'en-têtes (remarques E24, E33, E32) et des fiches de
correctifs (constat C25), hors ligne : les réponses HTTP sont construites
directement, sans requête.
"""

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from headers_analyzer import analyser_headers_reponse, SECURITY_HEADERS
from fiches import FICHES, ADAPTER_EN_TETE
from pdf_reporter import generer_rapport_pdf
from reporter import calculer_score

PRESENT = "En-tête présent (sa valeur n'est pas évaluée par l'outil)."


def reponse(**entetes):
    r = requests.Response()
    r.status_code = 200
    r.headers = CaseInsensitiveDict({nom.replace("_", "-"): v for nom, v in entetes.items()})
    r._content = b""
    return r


def par_en_tete(resultat):
    return {o["header"]: o for o in resultat["observations"]}


# ---------------------------------------------------------------------------
# E24 : X-Frame-Options ou CSP frame-ancestors
# ---------------------------------------------------------------------------

def test_x_frame_options_seul():
    obs = par_en_tete(analyser_headers_reponse(reponse(X_Frame_Options="DENY")))["X-Frame-Options"]
    assert (obs["niveau"], obs["message"]) == ("OK", PRESENT)


def test_frame_ancestors_seul():
    resultat = analyser_headers_reponse(reponse(
        Content_Security_Policy="default-src 'self'; frame-ancestors 'none'"))
    obs = par_en_tete(resultat)["X-Frame-Options"]
    assert obs["niveau"] == "OK"
    assert obs["message"] == "Protection assurée par la directive CSP frame-ancestors."
    assert obs["present"] is False


def test_ni_x_frame_options_ni_frame_ancestors():
    # Le mot « frame-ancestors » dans une autre directive ne compte pas.
    resultat = analyser_headers_reponse(reponse(
        Content_Security_Policy="default-src 'self' https://frame-ancestors.exemple"))
    assert par_en_tete(resultat)["X-Frame-Options"]["niveau"] == "CRITIQUE"
    assert par_en_tete(analyser_headers_reponse(reponse()))["X-Frame-Options"]["niveau"] == "CRITIQUE"


# ---------------------------------------------------------------------------
# E33 : Server et X-Powered-By
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("nom, valeur, niveau", [
    ("Server", "Apache/2.4.41", "INFO"),
    ("Server", "Vercel", "OK"),
    ("Server", "cloudflare", "OK"),
    ("X-Powered-By", "PHP/8.1.2", "INFO"),
    ("X-Powered-By", "Express", "OK"),
])
def test_divulgation_de_version(nom, valeur, niveau):
    obs = par_en_tete(analyser_headers_reponse(reponse(**{nom.replace("-", "_"): valeur})))[nom]
    assert obs["niveau"] == niveau
    if niveau == "OK":
        assert obs["message"] == "En-tête présent, sans numéro de version : rien d'exploitable divulgué."
    else:
        assert obs["message"] == "En-tête divulguant un numéro de version du logiciel."


def test_nombre_d_observations_identique():
    cas = [
        reponse(X_Frame_Options="DENY", Server="Apache/2.4.41", X_Powered_By="PHP/8.1.2"),
        reponse(Content_Security_Policy="frame-ancestors 'self'", Server="Vercel", X_Powered_By="Express"),
        reponse(Server="cloudflare", X_Powered_By="PHP/8.1.2"),
    ]
    nombres = {len(analyser_headers_reponse(r)["observations"]) for r in cas}
    assert nombres == {len(SECURITY_HEADERS) + 2}


# ---------------------------------------------------------------------------
# E32 : aucune valeur n'est évaluée
# ---------------------------------------------------------------------------

def test_valeur_jamais_evaluee():
    resultat = analyser_headers_reponse(reponse(
        Content_Security_Policy="default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        Strict_Transport_Security="max-age=0",
        X_Frame_Options="ALLOWALL",
        Referrer_Policy="unsafe-url",
    ))
    for nom in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "Referrer-Policy"):
        obs = par_en_tete(resultat)[nom]
        assert (obs["niveau"], obs["message"]) == ("OK", PRESENT)


# ---------------------------------------------------------------------------
# C25 : fiches de correctifs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("nom", list(SECURITY_HEADERS) + ["Server", "X-Powered-By"])
def test_fiches_d_en_tete_a_adapter(nom):
    assert FICHES[nom]["adapter"] == ADAPTER_EN_TETE
    assert "vercel.json" in ADAPTER_EN_TETE
    assert "ne bloque pas les services utilisés par le site" in ADAPTER_EN_TETE


def test_fiche_permissions_policy_camera():
    assert "camera=(self) plutôt que camera=()" in FICHES["Permissions-Policy"]["note"]


def test_pdf_avec_fiche_a_adapter():
    modules = [analyser_headers_reponse(reponse())]
    pdf = generer_rapport_pdf("https://exemple.test", modules, calculer_score(modules), 0.1,
                              "2026-10-14T12:00:00+00:00")
    assert pdf[:4] == b"%PDF"
