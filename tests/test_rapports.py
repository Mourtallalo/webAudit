"""
Tests des rapports (constat C26, constat C16) et de la traçabilité
(version de l'outil, date du référentiel CMS), hors ligne.
"""

import json
import os
import re

import pytest
import requests
from reportlab import rl_config
from requests.structures import CaseInsensitiveDict

import app as application
import moteur
import scanner
from pdf_reporter import generer_rapport_pdf
from reporter import calculer_score, generer_rapport_texte, PENALITES
from version import VERSION

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CSP_LONGUE = ("default-src 'self'; script-src 'self' https://cdn.exemple.test https://stats.exemple.test; "
              "style-src 'self' 'unsafe-inline' https://polices.exemple.test; img-src 'self' data: "
              "https://images.exemple.test; connect-src 'self' https://api.exemple.test; frame-ancestors 'none'")

MODULES = [
    {"module": "En-tetes HTTP", "statut": "succes", "message": "", "observations": [
        {"header": "Content-Security-Policy", "present": True, "valeur": CSP_LONGUE,
         "niveau": "OK", "message": "En-tête présent (sa valeur n'est pas évaluée par l'outil)."},
        {"header": "Strict-Transport-Security", "present": False, "valeur": None,
         "niveau": "CRITIQUE", "message": "En-tête absent."},
        {"header": "Referrer-Policy", "present": False, "valeur": None,
         "niveau": "AVERTISSEMENT", "message": "En-tête absent."},
        {"header": "Server", "present": True, "valeur": "Apache/2.4.41",
         "niveau": "INFO", "message": "En-tête divulguant un numéro de version du logiciel."},
    ]},
    {"module": "HTTPS / TLS", "statut": "succes", "message": "", "observations": [
        {"critere": "Disponibilité HTTPS", "niveau": "OK", "message": "Le serveur répond en HTTPS (port 443)."},
    ], "details": {"hote_tls": "exemple.test", "port_tls": 443}},
    {"module": "Detection CMS", "statut": "succes", "message": "", "observations": [
        {"critere": "Identification du CMS", "niveau": "OK", "message": "Aucun CMS standard détecté."},
    ]},
]


def rapport():
    score = calculer_score(MODULES)
    return generer_rapport_texte("https://exemple.test", MODULES, score, 1.5,
                                 "2026-10-14T12:00:00+00:00",
                                 url_finale="https://www.exemple.test/", hote_tls="exemple.test (port 443)")


# ---------------------------------------------------------------------------
# C26 : résumé recalculable et valeurs non tronquées
# ---------------------------------------------------------------------------

def test_resume_contient_les_cinq_lignes():
    texte = rapport()
    for ligne in ("  Problèmes critiques   : 1", "  Avertissements        : 1", "  Informations          : 1",
                  "  Points conformes      : 3", "  Points                : 70/100"):
        assert ligne in texte.splitlines()


def test_score_recalculable_depuis_le_resume():
    texte = rapport()
    nombre = lambda libelle: int(re.search(libelle + r"\s*: (\d+)", texte).group(1))
    recalcule = (100 - PENALITES["CRITIQUE"] * nombre("Problèmes critiques")
                 - PENALITES["AVERTISSEMENT"] * nombre("Avertissements")
                 - PENALITES["INFO"] * nombre("Informations"))
    assert "Points                : {}/100".format(recalcule) in texte


def test_aucune_valeur_tronquee():
    texte = rapport()
    assert not any(ligne.rstrip().endswith("...") for ligne in texte.splitlines())
    # La valeur entière se retrouve en recollant les lignes repliées.
    debut = texte.index("      Valeur : " + CSP_LONGUE[:20])
    lignes = []
    for ligne in texte[debut:].splitlines():
        if lignes and not ligne.startswith(" " * 15):
            break
        lignes.append(ligne)
    recolle = " ".join(l.strip() for l in lignes).replace("Valeur : ", "", 1)
    assert recolle == CSP_LONGUE
    assert all(len(l) <= 70 for l in lignes)
    assert len(lignes) > 1


def test_version_et_referentiel_dans_le_rapport_texte():
    texte = rapport()
    assert "Outil          : WebAudit {}".format(VERSION) in texte
    assert "Versions CMS   : Référence des versions relevée le 14/10/2026" in texte
    assert "Rapport généré par WebAudit {}".format(VERSION) in texte


# ---------------------------------------------------------------------------
# Traçabilité : version_outil dans le JSON
# ---------------------------------------------------------------------------

def test_version_dans_le_json(tmp_path, capsys):
    assert VERSION == "2.0.0"
    with pytest.raises(SystemExit):
        scanner.main(["inexistant.test", "--json", str(tmp_path / "r.json")])
    donnees = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert donnees["version_outil"] == "2.0.0"
    assert donnees["date_referentiel_cms"] == "2026-10-14"
    web = application.app.test_client().post("/api/scan", json={"url": "inexistant.test"}).get_json()
    assert web["version_outil"] == "2.0.0"


# ---------------------------------------------------------------------------
# PDF : quatre niveaux, version de l'outil, URL finale, date du référentiel
# ---------------------------------------------------------------------------

def test_pdf_affiche_niveaux_version_url_finale(monkeypatch):
    # Flux non compressés, pour pouvoir lire le texte du PDF.
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    pdf = generer_rapport_pdf("https://exemple.test", MODULES, calculer_score(MODULES), 1.5,
                              "2026-10-14T12:00:00+00:00", url_finale="https://www.exemple.test/fin",
                              version_outil="2.0.0", date_referentiel="2026-10-14")
    contenu = pdf.decode("latin-1")
    for texte in ("CRITIQUE", "SURVEILLER", "INFO", "CONFORME",
                  "WebAudit 2.0.0", "https://www.exemple.test/fin", "14/10/2026"):
        assert texte in contenu, texte


def test_pdf_depuis_l_api_transmet_les_champs(monkeypatch):
    recu = {}

    def faux_pdf(url, modules, score, duree, date_scan=None, **kwargs):
        recu.update(kwargs)
        return b"%PDF-factice"

    monkeypatch.setattr(application, "generer_rapport_pdf", faux_pdf)
    corps = {"url": "https://exemple.test", "modules": MODULES, "score": calculer_score(MODULES),
             "duree": 1, "url_finale": "https://www.exemple.test/", "version_outil": "2.0.0",
             "date_referentiel_cms": "2026-10-14", "statut": "complet"}
    reponse = application.app.test_client().post("/api/rapport-pdf", json=corps)
    assert reponse.status_code == 200
    assert recu == {"url_finale": "https://www.exemple.test/", "version_outil": "2.0.0",
                    "date_referentiel": "2026-10-14"}


# ---------------------------------------------------------------------------
# C16 : référence légale
# ---------------------------------------------------------------------------

def test_mention_legale_corrigee():
    assert "loi n°2008-11 du 25 janvier 2008 sur la cybercriminalité" in " ".join(scanner.__doc__.split())
    for dossier, _, fichiers in os.walk(RACINE):
        if any(x in dossier for x in (".git", ".venv", "__pycache__", ".pytest_cache")):
            continue
        for nom in fichiers:
            if nom.endswith((".py", ".md", ".js", ".html", ".txt", ".json", ".css")) and nom != "test_rapports.py":
                with open(os.path.join(dossier, nom), encoding="utf-8", errors="ignore") as f:
                    assert "2008-12" not in f.read(), os.path.join(dossier, nom)
