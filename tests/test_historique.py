"""
Tests de l'historique des scans (constat C01), hors ligne, avec une base
temporaire (fixture base_historique de conftest.py, dans tmp_path).
"""

import os
import sqlite3

import pytest

import app as application
import historique
import moteur
import scanner


def rapport(url="https://exemple.test", date="2026-10-14T10:00:00+00:00", points=72, note=None,
            statut="partiel", decompte=None):
    return {
        "url": url, "statut": statut, "date_scan": date, "version_outil": "2.0.0",
        "score": {"points": points, "note": note, "complet": statut == "complet",
                  "decompte": decompte or {"CRITIQUE": 1, "AVERTISSEMENT": 1, "INFO": 0, "OK": 9}},
    }


def test_base_dans_tmp_path(base_historique, tmp_path):
    assert base_historique == str(tmp_path / "historique.db")
    assert os.path.exists(base_historique)


def test_enregistrement_puis_lecture():
    assert historique.enregistrer_scan(rapport(points=96, note="A+", statut="complet",
                                               decompte={"CRITIQUE": 0, "AVERTISSEMENT": 0,
                                                         "INFO": 2, "OK": 10})) is True
    assert historique.historique_pour("exemple.test") == [{
        "url": "https://exemple.test",
        "date_scan": "2026-10-14T10:00:00+00:00",
        "note": "A+",
        "points": 96,
        "decompte": {"CRITIQUE": 0, "AVERTISSEMENT": 0, "INFO": 2, "OK": 10},
        "complet": True,
        "version_outil": "2.0.0",
    }]


def test_ordre_chronologique_et_limite():
    # Enregistrés dans le désordre : la lecture suit les dates.
    for jour, points in ((12, 60), (10, 40), (14, 90), (11, 50), (13, 70)):
        historique.enregistrer_scan(rapport(date="2026-10-{:02d}T09:00:00+00:00".format(jour), points=points))
    historique.enregistrer_scan(rapport(url="https://autre.test", points=10))

    scans = historique.historique_pour("https://exemple.test/page")
    assert [s["points"] for s in scans] == [40, 50, 60, 70, 90]
    # Avec une limite, ce sont les plus récents, toujours du plus ancien au plus récent.
    assert [s["points"] for s in historique.historique_pour("exemple.test", limite=2)] == [70, 90]


def test_scan_impossible_non_enregistre():
    assert historique.enregistrer_scan(rapport(statut="impossible", points=None)) is False
    assert historique.historique_pour("exemple.test") == []


# ---------------------------------------------------------------------------
# Intégration à l'API
# ---------------------------------------------------------------------------

@pytest.fixture
def scan_factice(monkeypatch, dns):
    dns["exemple.test"] = ["1.1.1.1"]
    resultats = []

    def faux_scan(url, timeout=10, autoriser_local=False):
        return resultats.pop(0)

    monkeypatch.setattr(application, "lancer_scan", faux_scan)
    monkeypatch.setattr(scanner, "lancer_scan", faux_scan)
    return resultats


def scanner_via_api(url="exemple.test"):
    return application.app.test_client().post("/api/scan", json={"url": url, "autorisation": True})


def test_api_scan_enregistre_puis_api_history(scan_factice):
    scan_factice.extend([
        rapport(date="2026-10-13T08:00:00+00:00", points=72),
        rapport(date="2026-10-14T08:00:00+00:00", points=96, note="A+", statut="complet"),
    ])
    assert scanner_via_api().status_code == 200
    assert scanner_via_api().status_code == 200

    reponse = application.app.test_client().get("/api/history?url=https://exemple.test")
    assert reponse.status_code == 200
    donnees = reponse.get_json()
    assert donnees["hote"] == "exemple.test"
    assert [(s["points"], s["note"]) for s in donnees["scans"]] == [(72, None), (96, "A+")]


def test_api_scan_impossible_non_enregistre():
    reponse = scanner_via_api("inexistant.test")
    assert reponse.get_json()["statut"] == "impossible"
    assert historique.historique_pour("inexistant.test") == []


def test_erreur_d_ecriture_ne_fait_pas_echouer_le_scan(scan_factice, monkeypatch):
    scan_factice.append(rapport())

    def ecriture_impossible(rapport):
        raise sqlite3.OperationalError("disque plein (simulé)")

    monkeypatch.setattr(historique, "enregistrer_scan", ecriture_impossible)
    reponse = scanner_via_api()
    assert reponse.status_code == 200
    assert reponse.get_json()["score"]["points"] == 72


@pytest.mark.parametrize("parametre, code", [
    ("", 400),
    ("?url=", 400),
    ("?url=localtest.me", 400),       # même filtre anti-SSRF qu'à /api/scan
    ("?url=inexistant.test", 200),    # nom introuvable : historique simplement vide
])
def test_api_history_validation(dns, parametre, code):
    dns["localtest.me"] = ["127.0.0.1"]
    reponse = application.app.test_client().get("/api/history" + parametre)
    assert reponse.status_code == code
    if code == 200:
        assert reponse.get_json() == {"hote": "inexistant.test", "scans": []}


def test_ligne_de_commande_n_ecrit_rien(scan_factice, capsys):
    scan_factice.append(dict(rapport(), rapport_texte="rapport factice"))
    scanner.main(["exemple.test", "--autorise"])
    assert historique.historique_pour("exemple.test") == []
