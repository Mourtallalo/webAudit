"""
app.py
======
Application web Flask pour WebAudit.

Sert une interface web permettant de lancer un audit de securite sur
une URL et d'afficher le rapport genere par les modules existants
(headers_analyzer, https_checker, cms_detector, reporter).

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import json
import re
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, Response

from moteur import lancer_scan, normaliser_url
from reseau import valider_cible, forme_url_valide, MOTIF_NOM_INTROUVABLE
from fiches import FICHES
from pdf_reporter import generer_rapport_pdf

app = Flask(__name__)

# Delai maximum (secondes) accorde a chaque requete reseau du scanner
TIMEOUT = 10

# Nombre maximum d'URL acceptees par la page de comparaison. Les scans y
# sont enchaines un par un : cette borne evite de lancer une campagne
# interminable, et limite la charge imposee aux serveurs audites.
MAX_URLS_COMPARAISON = 30

# La base de connaissances est injectee telle quelle dans les pages.
# On neutralise le chevron ouvrant : sans cela, la sequence </script>
# qui pourrait apparaitre dans un correctif fermerait la balise.
FICHES_JSON = json.dumps(FICHES, ensure_ascii=False).replace("<", "\\u003c")


@app.route("/")
def index():
    """Page d'accueil avec le formulaire de saisie d'URL."""
    return render_template("index.html", fiches_json=FICHES_JSON)


@app.route("/comparer")
def comparer():
    """Page de comparaison : plusieurs sites audites l'un apres l'autre."""
    return render_template("comparer.html", max_urls=MAX_URLS_COMPARAISON)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Lance un audit complet sur l'URL fournie et retourne le rapport en JSON.

    Corps attendu : { "url": "https://exemple.com" }
    """
    data = request.get_json(silent=True) or {}
    url_brute = data.get("url", "")

    if not url_brute:
        return jsonify({"erreur": "Merci de saisir une URL."}), 400

    url = normaliser_url(url_brute)

    # Filtre anti-SSRF (reseau.valider_cible) : toutes les adresses résolues
    # doivent être publiques. Un nom introuvable n'est pas refusé ici : le
    # scan est alors déclaré « impossible » par le moteur (E15).
    ok, motif = valider_cible(url)
    if not ok and motif != MOTIF_NOM_INTROUVABLE:
        return jsonify({"erreur": "Cible refusée : {}.".format(motif)}), 400

    # Le scan lui-même est confié au moteur commun (moteur.py), partagé
    # avec la ligne de commande (scanner.py).
    try:
        resultat = lancer_scan(url, timeout=TIMEOUT)
    except Exception as e:
        return jsonify({"erreur": "Erreur inattendue pendant le scan : {}".format(str(e))}), 500

    return jsonify(resultat)


@app.route("/api/rapport-pdf", methods=["POST"])
def api_rapport_pdf():
    """
    Met en page un rapport deja produit et le renvoie au format PDF.

    Le client renvoie le resultat que /api/scan lui a donne : on ne
    relance pas le scan, pour que le PDF corresponde exactement a ce que
    l'utilisateur a sous les yeux.

    Corps attendu : la reponse complete de /api/scan.
    """
    data = request.get_json(silent=True) or {}

    url = normaliser_url(str(data.get("url", "")))
    modules = data.get("modules")
    score = data.get("score")

    if not forme_url_valide(url) or not isinstance(modules, list) or not isinstance(score, dict):
        return jsonify({"erreur": "Rapport incomplet ou invalide."}), 400

    if data.get("statut") == "impossible":
        return jsonify({"erreur": "Scan impossible : aucun rapport PDF à produire."}), 400

    # Les modules sont relus depuis le client : on ne garde que les
    # dictionnaires, pour ne pas faire echouer la mise en page sur une
    # structure inattendue.
    modules = [m for m in modules if isinstance(m, dict)]

    try:
        duree = round(float(data.get("duree", 0)), 2)
    except (TypeError, ValueError):
        duree = 0

    try:
        pdf = generer_rapport_pdf(url, modules, score, duree, data.get("date_scan"),
                                  url_finale=data.get("url_finale"),
                                  version_outil=data.get("version_outil"),
                                  date_referentiel=data.get("date_referentiel_cms"))
    except Exception:
        app.logger.exception("Echec de la generation du rapport PDF")
        return jsonify({"erreur": "Le rapport PDF n'a pas pu etre genere."}), 500

    hote = urlparse(url).hostname or "rapport"
    nom_fichier = "webaudit-{}.pdf".format(re.sub(r"[^a-zA-Z0-9.-]", "_", hote))

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="{}"'.format(nom_fichier)},
    )


if __name__ == "__main__":
    import os
    # Mode debug desactive par defaut : de bonnes pratiques de securite
    # imposent de ne jamais exposer le debogueur Flask par defaut, a plus
    # forte raison pour un outil d'audit de securite. Activer explicitement
    # avec FLASK_DEBUG=1 pendant le developpement si necessaire.
    debug_active = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_active, host="127.0.0.1", port=5000)
