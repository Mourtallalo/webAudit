"""
historique.py
=============
Historique des scans de l'interface web (constat C01).

Une petite base SQLite (module sqlite3 de la bibliothèque standard),
par défaut instance/historique.db, conserve pour chaque scan abouti :
l'hôte, l'URL saisie, la date, la note, les points, le décompte des
quatre niveaux, l'indicateur « audit complet » et la version de l'outil.

Rien d'autre n'est conservé (ni le détail des observations, ni le
consentement de l'utilisateur). Pour tout effacer : supprimer le fichier
instance/historique.db.

La ligne de commande n'écrit rien dans cet historique.

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import os
import sqlite3
from contextlib import closing
from urllib.parse import urlparse

CHEMIN_DEFAUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "historique.db")

_chemin = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hote          TEXT    NOT NULL,
    url           TEXT    NOT NULL,
    date_scan     TEXT    NOT NULL,
    note          TEXT,
    points        INTEGER,
    critique      INTEGER NOT NULL,
    avertissement INTEGER NOT NULL,
    info          INTEGER NOT NULL,
    ok            INTEGER NOT NULL,
    complet       INTEGER NOT NULL,
    version_outil TEXT
);
CREATE INDEX IF NOT EXISTS scans_par_hote ON scans (hote, date_scan);
"""


def initialiser(chemin=None):
    """Crée la base (et son dossier) si besoin ; renvoie son chemin."""
    global _chemin
    _chemin = chemin or CHEMIN_DEFAUT
    os.makedirs(os.path.dirname(os.path.abspath(_chemin)), exist_ok=True)
    with closing(sqlite3.connect(_chemin)) as base, base:
        base.executescript(SCHEMA)
    return _chemin


def _connecter():
    if _chemin is None:
        initialiser()
    return closing(sqlite3.connect(_chemin))


def hote_de(url):
    """Nom d'hôte d'une URL, en minuscules (https:// ajouté si le schéma manque)."""
    url = str(url or "").strip()
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


def enregistrer_scan(rapport):
    """
    Enregistre un scan abouti (réponse de /api/scan).

    Un scan « impossible » n'est pas enregistré : il n'a rien mesuré.

    Retour
    ------
    bool : True si le scan a été enregistré.
    """
    if rapport.get("statut") == "impossible":
        return False
    score = rapport.get("score") or {}
    decompte = score.get("decompte") or {}
    with _connecter() as base, base:
        base.execute(
            "INSERT INTO scans (hote, url, date_scan, note, points, critique, avertissement,"
            " info, ok, complet, version_outil) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                hote_de(rapport.get("url")),
                rapport.get("url"),
                rapport.get("date_scan"),
                score.get("note"),
                score.get("points"),
                decompte.get("CRITIQUE", 0),
                decompte.get("AVERTISSEMENT", 0),
                decompte.get("INFO", 0),
                decompte.get("OK", 0),
                1 if score.get("complet") else 0,
                rapport.get("version_outil"),
            ),
        )
    return True


def historique_pour(url, limite=30):
    """
    Les scans enregistrés pour l'hôte de l'URL, du plus ancien au plus récent.

    Seuls les « limite » scans les plus récents sont renvoyés.
    """
    with _connecter() as base:
        lignes = base.execute(
            "SELECT url, date_scan, note, points, critique, avertissement, info, ok, complet,"
            " version_outil FROM scans WHERE hote = ? ORDER BY date_scan DESC, id DESC LIMIT ?",
            (hote_de(url), int(limite)),
        ).fetchall()
    scans = [{
        "url": url_saisie,
        "date_scan": date_scan,
        "note": note,
        "points": points,
        "decompte": {"CRITIQUE": critique, "AVERTISSEMENT": avertissement, "INFO": info, "OK": ok},
        "complet": bool(complet),
        "version_outil": version_outil,
    } for (url_saisie, date_scan, note, points, critique, avertissement, info, ok, complet,
           version_outil) in lignes]
    scans.reverse()
    return scans
