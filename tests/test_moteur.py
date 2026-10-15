"""
Tests du moteur d'analyse unique (remarque C02), hors ligne.

La récupération de la page et les trois modules d'analyse sont remplacés
par des fonctions factices : aucune requête réseau n'est émise. On
vérifie que la ligne de commande (scanner.py) et l'interface web
(/api/scan) renvoient le même résultat.
"""

import json

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import app as application
import moteur
import scanner

URL = "https://exemple.test"


def fausse_reponse(url):
    reponse = requests.Response()
    reponse.status_code = 200
    reponse.url = url
    reponse.headers = CaseInsensitiveDict({"X-Frame-Options": "DENY"})
    reponse._content = b"<html></html>"
    reponse.encoding = "utf-8"
    return reponse


def faux_headers(reponse):
    return {
        "module": "En-tetes HTTP",
        "statut": "succes",
        "message": "",
        "observations": [
            {"header": "Content-Security-Policy", "present": False, "valeur": None,
             "niveau": "CRITIQUE", "message": "En-tête absent."},
            {"header": "X-Frame-Options", "present": True, "valeur": "DENY",
             "niveau": "OK", "message": "En-tête présent."},
        ],
        "headers_bruts": {"Server": "factice"},
    }


def faux_https(url, timeout=10, autoriser_local=False):
    return {
        "module": "HTTPS / TLS",
        "statut": "succes",
        "message": "",
        "observations": [
            {"critere": "Redirection HTTP vers HTTPS", "niveau": "AVERTISSEMENT",
             "message": "Pas de redirection."},
        ],
        "details": {"hote_tls": "exemple.test"},
    }


def faux_cms(reponse):
    return {
        "module": "Detection CMS",
        "statut": "erreur",
        "message": "Erreur factice.",
        "observations": [],
    }


@pytest.fixture
def modules_factices(monkeypatch, dns):
    """Remplace la récupération de la page et les trois modules."""
    dns["exemple.test"] = ["1.1.1.1"]  # adresse publique : acceptée par le filtre
    appels = []

    def fausse_recuperation(url, timeout, autoriser_local=False):
        appels.append(("recuperer_page", url, timeout))
        return fausse_reponse(url), [url]

    def espion(nom, fonction):
        def enveloppe(*args, **kwargs):
            appels.append((nom, args, kwargs.get("timeout")))
            return fonction(*args, **kwargs)
        return enveloppe

    monkeypatch.setattr(moteur, "recuperer_page", fausse_recuperation)
    monkeypatch.setattr(moteur, "analyser_headers_reponse", espion("headers", faux_headers))
    monkeypatch.setattr(moteur, "verifier_https", espion("https", faux_https))
    monkeypatch.setattr(moteur, "detecter_cms_reponse", espion("cms", faux_cms))
    return appels


def scan_ligne_de_commande(tmp_path, url):
    chemin = tmp_path / "rapport.json"
    scanner.main(["--autorise", url, "--json", str(chemin)])
    return json.loads(chemin.read_text(encoding="utf-8"))


def scan_interface_web(url):
    client = application.app.test_client()
    reponse = client.post("/api/scan", json={"autorisation": True, "url": url})
    assert reponse.status_code == 200, reponse.get_json()
    return reponse.get_json()


def test_meme_resultat_ligne_de_commande_et_interface_web(modules_factices, tmp_path, capsys):
    cli = scan_ligne_de_commande(tmp_path, URL)
    web = scan_interface_web(URL)

    assert set(cli) == set(web) == {
        "url", "url_finale", "redirections", "hote_tls", "statut", "motif", "remarque",
        "version_outil", "date_referentiel_cms",
        "date_scan", "duree", "score", "modules", "rapport_texte"}
    assert cli["url"] == web["url"] == URL
    assert cli["score"] == web["score"]
    assert cli["modules"] == web["modules"]
    assert cli["statut"] == web["statut"] == "partiel"

    # La page est récupérée une seule fois par scan (E42), puis les trois
    # modules sont appelés, par chacun des deux points d'entrée.
    assert [a[0] for a in modules_factices] == ["recuperer_page", "headers", "cms", "https"] * 2


def test_score_calcule_par_reporter(modules_factices, tmp_path, capsys):
    cli = scan_ligne_de_commande(tmp_path, URL)
    # CRITIQUE 20 + AVERTISSEMENT 8 = 28 points retirés ; module CMS en
    # erreur : audit partiel, donc pas de note.
    assert cli["score"]["points"] == 72
    assert cli["score"]["note"] is None
    assert cli["score"]["complet"] is False
    assert cli["score"]["modules_non_executes"] == ["Detection CMS"]


def test_en_tetes_bruts_retires(modules_factices, tmp_path, capsys):
    cli = scan_ligne_de_commande(tmp_path, URL)
    web = scan_interface_web(URL)
    for resultat in (cli, web):
        assert all("headers_bruts" not in m for m in resultat["modules"])


def test_normalisation_identique(modules_factices, tmp_path, capsys):
    cli = scan_ligne_de_commande(tmp_path, "  exemple.test ")
    web = scan_interface_web("  exemple.test ")
    assert cli["url"] == web["url"] == "https://exemple.test"


def test_timeout_transmis(modules_factices, tmp_path, capsys):
    scanner.main(["--autorise", URL, "--timeout", "3", "--json", str(tmp_path / "r.json")])
    timeouts = {a[2] for a in modules_factices if a[0] in ("recuperer_page", "https")}
    assert timeouts == {3}


def test_fichier_texte_identique_au_rapport(modules_factices, tmp_path, capsys):
    chemin_txt = tmp_path / "rapport.txt"
    chemin_json = tmp_path / "rapport.json"
    scanner.main(["--autorise", URL, "--texte", str(chemin_txt), "--json", str(chemin_json)])
    rapport = json.loads(chemin_json.read_text(encoding="utf-8"))
    assert chemin_txt.read_text(encoding="utf-8") == rapport["rapport_texte"]
    assert rapport["rapport_texte"] in capsys.readouterr().out


def test_url_finale_et_hote_tls(modules_factices, tmp_path, capsys):
    cli = scan_ligne_de_commande(tmp_path, URL)
    assert cli["url_finale"] == URL
    assert cli["redirections"] == [URL]
    assert cli["hote_tls"] == "exemple.test"
    assert "URL saisie     : https://exemple.test" in cli["rapport_texte"]
    assert "URL analysée   : https://exemple.test" in cli["rapport_texte"]
    assert "Hôte TLS       : exemple.test" in cli["rapport_texte"]
