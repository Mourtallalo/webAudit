"""
app.py
======
Application web Flask pour WebAudit.

Sert une interface web permettant de lancer un audit de sécurité sur
une URL et d'afficher le rapport généré par les modules existants
(headers_analyzer, https_checker, cms_detector, reporter).

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import json
import re
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, Response

from moteur import lancer_scan, normaliser_url
from reseau import valider_cible, forme_url_valide, MOTIF_NOM_INTROUVABLE
from fiches import FICHES
import historique
from pdf_reporter import generer_rapport_pdf

app = Flask(__name__)

# Délai maximum (secondes) accordé à chaque requête réseau du scanner
TIMEOUT = 10

# Nombre maximum d'URL acceptées par la page de comparaison. Les scans y
# sont enchaînés un par un : cette borne évite de lancer une campagne
# interminable, et limite la charge imposée aux serveurs audités.
MAX_URLS_COMPARAISON = 30

MESSAGE_AUTORISATION = "Confirmez que vous êtes autorisé à auditer ce site."

# La base de connaissances est injectée telle quelle dans les pages.
# On neutralise le chevron ouvrant : sans cela, la séquence </script>
# qui pourrait apparaître dans un correctif fermerait la balise.
FICHES_JSON = json.dumps(FICHES, ensure_ascii=False).replace("<", "\\u003c")


@app.route("/")
def index():
    """Page d'accueil avec le formulaire de saisie d'URL."""
    return render_template("index.html", fiches_json=FICHES_JSON)


@app.route("/comparer")
def comparer():
    """Page de comparaison : plusieurs sites audités l'un après l'autre."""
    return render_template("comparer.html", max_urls=MAX_URLS_COMPARAISON)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Lance un audit complet sur l'URL fournie et retourne le rapport en JSON.

    Corps attendu : { "url": "https://exemple.com" }
    """
    data = request.get_json(silent=True) or {}
    url_brute = data.get("url", "")

    # E26 : la case cochée dans le navigateur ne suffit pas ; l'API exige
    # elle-même la confirmation. Rien n'est enregistré à ce sujet.
    if data.get("autorisation") is not True:
        return jsonify({"erreur": MESSAGE_AUTORISATION}), 400

    if not url_brute:
        return jsonify({"erreur": "Merci de saisir une URL."}), 400

    url = normaliser_url(url_brute)

    refus = _refus_cible(url)
    if refus:
        return refus

    # Le scan lui-même est confié au moteur commun (moteur.py), partagé
    # avec la ligne de commande (scanner.py).
    try:
        resultat = lancer_scan(url, timeout=TIMEOUT)
    except Exception as e:
        return jsonify({"erreur": "Erreur inattendue pendant le scan : {}".format(str(e))}), 500

    # C01 : historique des scans aboutis. Un scan « impossible » n'est pas
    # enregistré, et une erreur d'écriture ne fait jamais échouer le scan.
    if resultat.get("statut") != "impossible":
        try:
            historique.enregistrer_scan(resultat)
        except Exception:
            app.logger.exception("Échec de l'enregistrement dans l'historique")

    return jsonify(resultat)


@app.route("/api/history", methods=["GET"])
def api_history():
    """
    Historique des scans d'un hôte, du plus ancien au plus récent (C01).

    Paramètre : ?url=exemple.com (même validation qu'à /api/scan).
    Réponse : {"hote": ..., "scans": [...]}.
    """
    url_brute = request.args.get("url", "")
    if not url_brute.strip():
        return jsonify({"erreur": "Merci de saisir une URL."}), 400

    url = normaliser_url(url_brute)
    refus = _refus_cible(url)
    if refus:
        return refus

    return jsonify({"hote": historique.hote_de(url), "scans": historique.historique_pour(url)})


def _refus_cible(url):
    """
    Filtre anti-SSRF (reseau.valider_cible) : toutes les adresses résolues
    doivent être publiques. Un nom introuvable n'est pas refusé ici : le
    scan est alors déclaré « impossible » par le moteur (E15).

    Retour
    ------
    None si la cible est acceptée, sinon la réponse d'erreur 400.
    """
    ok, motif = valider_cible(url)
    if not ok and motif != MOTIF_NOM_INTROUVABLE:
        return jsonify({"erreur": "Cible refusée : {}.".format(motif)}), 400
    return None


@app.route("/api/rapport-pdf", methods=["POST"])
def api_rapport_pdf():
    """
    Met en page un rapport déjà produit et le renvoie au format PDF.

    Le client renvoie le résultat que /api/scan lui a donné : on ne
    relance pas le scan, pour que le PDF corresponde exactement à ce que
    l'utilisateur a sous les yeux.

    Corps attendu : la réponse complète de /api/scan.
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
    # dictionnaires, pour ne pas faire échouer la mise en page sur une
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
    # Mode debug désactivé par défaut : de bonnes pratiques de sécurité
    # imposent de ne jamais exposer le débogueur Flask par défaut, à plus
    # forte raison pour un outil d'audit de sécurité. Activer explicitement
    # avec FLASK_DEBUG=1 pendant le développement si nécessaire.
    debug_active = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_active, host="127.0.0.1", port=5000)
