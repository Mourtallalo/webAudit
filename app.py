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
import time
import re
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, Response

from headers_analyzer import analyser_headers
from https_checker import verifier_https
from cms_detector import detecter_cms
from reporter import calculer_score, generer_rapport_texte
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


def normaliser_url(url):
    """S'assure que l'URL commence par un schema. Prefixe avec https:// par defaut."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def url_valide(url):
    """Validation minimale : un hote avec au moins un point, pas d'espaces."""
    try:
        analyse = urlparse(url)
        if not analyse.hostname:
            return False
        if " " in url:
            return False
        # Rejette les hotes locaux/prives pour eviter les abus (SSRF basique)
        hote = analyse.hostname.lower()
        if hote in ("localhost", "127.0.0.1", "0.0.0.0") or hote.startswith("192.168.") or hote.startswith("10."):
            return False
        return bool(re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", hote))
    except Exception:
        return False


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

    if not url_valide(url):
        return jsonify({"erreur": "Cette URL ne semble pas valide. Verifiez le format (ex. suncom.app)."}), 400

    debut = time.time()
    # Horodatage unique de l'audit, avec le fuseau du serveur : il est repris
    # tel quel par l'interface, les exports .txt/.json et le rapport PDF.
    date_scan = datetime.now().astimezone().isoformat(timespec="seconds")
    resultats = []

    try:
        resultats.append(analyser_headers(url, timeout=TIMEOUT))
        resultats.append(verifier_https(url, timeout=TIMEOUT))
        resultats.append(detecter_cms(url, timeout=TIMEOUT))
    except Exception as e:
        return jsonify({"erreur": "Erreur inattendue pendant le scan : {}".format(str(e))}), 500

    duree = round(time.time() - debut, 2)
    score = calculer_score(resultats)
    rapport_texte = generer_rapport_texte(url, resultats, score, duree, date_scan)

    # On retire les en-tetes bruts complets : ils ne sont pas affiches et
    # peuvent etre volumineux. En revanche "details" est conserve : il est
    # compact, et porte les champs exploites par la comparaison multi-sites
    # (CMS detecte, disponibilite HTTPS) ainsi que par le rapport PDF.
    for module in resultats:
        module.pop("headers_bruts", None)

    return jsonify({
        "url": url,
        "date_scan": date_scan,
        "duree": duree,
        "score": score,
        "modules": resultats,
        "rapport_texte": rapport_texte,
    })


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

    if not url_valide(url) or not isinstance(modules, list) or not isinstance(score, dict):
        return jsonify({"erreur": "Rapport incomplet ou invalide."}), 400

    # Les modules sont relus depuis le client : on ne garde que les
    # dictionnaires, pour ne pas faire echouer la mise en page sur une
    # structure inattendue.
    modules = [m for m in modules if isinstance(m, dict)]

    try:
        duree = round(float(data.get("duree", 0)), 2)
    except (TypeError, ValueError):
        duree = 0

    try:
        pdf = generer_rapport_pdf(url, modules, score, duree, data.get("date_scan"))
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
