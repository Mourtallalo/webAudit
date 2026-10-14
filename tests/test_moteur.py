"""
Tests du moteur d'analyse unique (remarque C02), hors ligne.

Les trois modules d'analyse sont remplacés par des fonctions factices :
aucune requête réseau n'est émise. On vérifie que la ligne de commande
(scanner.py) et l'interface web (/api/scan) renvoient le même résultat.
"""

import json

import pytest

import app as application
import moteur
import scanner

URL = "https://exemple.test"


def faux_headers(url, timeout=10):
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


def faux_https(url, timeout=10):
    return {
        "module": "HTTPS/TLS",
        "statut": "succes",
        "message": "",
        "observations": [
            {"critere": "Redirection HTTPS", "niveau": "AVERTISSEMENT",
             "message": "Pas de redirection."},
        ],
        "details": {"https_disponible": True},
    }


def faux_cms(url, timeout=10):
    return {
        "module": "Detection CMS",
        "statut": "erreur",
        "message": "Délai dépassé (factice).",
        "observations": [],
    }


@pytest.fixture
def modules_factices(monkeypatch):
    """Remplace les trois modules d'analyse appelés par le moteur."""
    appels = []

    def espion(fonction):
        def enveloppe(url, timeout=10):
            appels.append((fonction.__name__, url, timeout))
            return fonction(url, timeout=timeout)
        return enveloppe

    monkeypatch.setattr(moteur, "analyser_headers", espion(faux_headers))
    monkeypatch.setattr(moteur, "verifier_https", espion(faux_https))
    monkeypatch.setattr(moteur, "detecter_cms", espion(faux_cms))
    return appels


def scan_ligne_de_commande(tmp_path, url):
    chemin = tmp_path / "rapport.json"
    scanner.main([url, "--json", str(chemin)])
    return json.loads(chemin.read_text(encoding="utf-8"))


def scan_interface_web(url):
    client = application.app.test_client()
    reponse = client.post("/api/scan", json={"url": url})
    assert reponse.status_code == 200, reponse.get_json()
    return reponse.get_json()


def test_meme_resultat_ligne_de_commande_et_interface_web(modules_factices, tmp_path, capsys):
    cli = scan_ligne_de_commande(tmp_path, URL)
    web = scan_interface_web(URL)

    assert set(cli) == set(web) == {"url", "date_scan", "duree", "score", "modules", "rapport_texte"}
    assert cli["url"] == web["url"] == URL
    assert cli["score"] == web["score"]
    assert cli["modules"] == web["modules"]

    # Les trois modules ont bien été appelés par chacun des deux points d'entrée.
    assert [nom for nom, _, _ in modules_factices] == [
        "faux_headers", "faux_https", "faux_cms"] * 2


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
    scanner.main([URL, "--timeout", "3", "--json", str(tmp_path / "r.json")])
    assert {t for _, _, t in modules_factices} == {3}


def test_fichier_texte_identique_au_rapport(modules_factices, tmp_path, capsys):
    chemin_txt = tmp_path / "rapport.txt"
    chemin_json = tmp_path / "rapport.json"
    scanner.main([URL, "--texte", str(chemin_txt), "--json", str(chemin_json)])
    rapport = json.loads(chemin_json.read_text(encoding="utf-8"))
    assert chemin_txt.read_text(encoding="utf-8") == rapport["rapport_texte"]
    assert rapport["rapport_texte"] in capsys.readouterr().out
