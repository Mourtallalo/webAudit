"""
Tests de la confirmation d'autorisation (remarque E26), hors ligne :
le scan lui-même est remplacé par une fonction factice.
"""

import io
import json

import pytest

import app as application
import moteur
import scanner

MESSAGE = "Confirmez que vous êtes autorisé à auditer ce site."


@pytest.fixture
def scan_factice(monkeypatch, dns):
    """Remplace lancer_scan (côté API et ligne de commande) et compte les appels."""
    dns["exemple.test"] = ["1.1.1.1"]
    appels = []

    def faux_scan(url, timeout=10, autoriser_local=False):
        appels.append((url, autoriser_local))
        return {"url": moteur.normaliser_url(url), "statut": "complet", "motif": None,
                "score": {"points": 100, "note": "A+"}, "modules": [], "rapport_texte": "rapport factice"}

    monkeypatch.setattr(application, "lancer_scan", faux_scan)
    monkeypatch.setattr(scanner, "lancer_scan", faux_scan)
    return appels


def poster(corps):
    return application.app.test_client().post("/api/scan", json=corps)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("corps", [
    {"url": "exemple.test"},
    {"url": "exemple.test", "autorisation": False},
    {"url": "exemple.test", "autorisation": "true"},  # une chaîne n'est pas true
    {"url": "exemple.test", "autorisation": 1},
])
def test_api_sans_autorisation_refuse(scan_factice, corps):
    reponse = poster(corps)
    assert reponse.status_code == 400
    assert reponse.get_json() == {"erreur": MESSAGE}
    assert scan_factice == []


def test_api_avec_autorisation_lance_le_scan(scan_factice):
    reponse = poster({"url": "exemple.test", "autorisation": True})
    assert reponse.status_code == 200
    assert reponse.get_json()["score"]["note"] == "A+"
    assert scan_factice == [("https://exemple.test", False)]


# ---------------------------------------------------------------------------
# Ligne de commande
# ---------------------------------------------------------------------------

class EntreeNonInteractive(io.StringIO):
    def isatty(self):
        return False


class EntreeInteractive(io.StringIO):
    def isatty(self):
        return True


def test_cli_sans_autorise_entree_non_interactive(scan_factice, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", EntreeNonInteractive("o\n"))
    with pytest.raises(SystemExit) as sortie:
        scanner.main(["exemple.test"])
    assert sortie.value.code == 3
    assert scan_factice == []
    assert "autorisation non confirmée" in capsys.readouterr().err


@pytest.mark.parametrize("reponse", ["n\n", "\n", "oui\n", ""])
def test_cli_reponse_autre_que_o(scan_factice, monkeypatch, capsys, reponse):
    monkeypatch.setattr("sys.stdin", EntreeInteractive(reponse))
    with pytest.raises(SystemExit) as sortie:
        scanner.main(["exemple.test"])
    assert sortie.value.code == 3
    assert scan_factice == []


def test_cli_question_posee_avec_l_hote(scan_factice, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", EntreeInteractive("o\n"))
    scanner.main(["https://exemple.test/page"])
    assert "Êtes-vous autorisé à auditer exemple.test ? (o/N) " in capsys.readouterr().out
    assert scan_factice == [("https://exemple.test/page", True)]


def test_cli_avec_autorise_lance_le_scan(scan_factice, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.stdin", EntreeNonInteractive(""))
    chemin = tmp_path / "r.json"
    scanner.main(["exemple.test", "--autorise", "--json", str(chemin)])
    assert scan_factice == [("exemple.test", True)]
    assert json.loads(chemin.read_text(encoding="utf-8"))["score"]["note"] == "A+"
