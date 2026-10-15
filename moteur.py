"""
moteur.py
=========
Moteur d'analyse unique de WebAudit (remarque C02).

La ligne de commande (scanner.py) et l'interface web (app.py) appellent
toutes deux lancer_scan() : un même scan donne donc le même résultat,
quelle que soit la façon de le lancer.

La page est récupérée une seule fois (E42) par reseau.recuperer_page,
puis transmise au module d'en-têtes et au module CMS. Le module HTTPS
garde sa propre connexion TLS et sa vérification de la redirection
HTTP → HTTPS.

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import time
from datetime import datetime

import headers_analyzer
import cms_detector
import https_checker
from headers_analyzer import analyser_headers_reponse
from https_checker import verifier_https
from cms_detector import detecter_cms_reponse
from reporter import calculer_score, generer_rapport_texte, generer_rapport_impossible
from reseau import recuperer_page, ErreurRecuperation
from version import VERSION

# Mention ajoutée au JSON et au rapport texte quand la page a dû être
# récupérée sans vérification du certificat (E36).
REMARQUE_SANS_VERIFICATION = (
    "Page récupérée sans vérification du certificat, celui-ci ayant été refusé (voir le module HTTPS)")


def normaliser_url(url):
    """S'assure que l'URL commence par un schéma. Préfixe avec https:// par défaut."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _module_en_erreur(nom_module, message):
    """Résultat d'un module qui n'a pas pu s'exécuter (audit partiel)."""
    return {"module": nom_module, "statut": "erreur", "message": message, "observations": []}


def lancer_scan(url, timeout=10, autoriser_local=False):
    """
    Exécute les trois modules d'analyse sur l'URL et produit le rapport.

    autoriser_local : True uniquement pour la ligne de commande, qui tourne
    sur le poste de l'auditeur ; l'interface web garde la valeur False.

    Trois issues possibles (clé « statut ») :
      - « complet »    : tous les modules ont abouti ; points et note ;
      - « partiel »    : la cible répond mais un module est en erreur ;
                         des points, sans note (reporter.calculer_score) ;
      - « impossible » : la cible est injoignable (nom introuvable,
                         connexion refusée, délai dépassé, E15) ; ni points
                         ni note, et un motif.

    Un certificat refusé ne rend pas le scan impossible : la page est
    récupérée sans vérification (clé « remarque »). Une autre erreur TLS
    (version refusée…) donne un audit partiel (E36, E35).

    Retour
    ------
    dict : {url, url_finale, redirections, hote_tls, statut, motif,
    remarque, version_outil, date_referentiel_cms, date_scan, duree, score,
    modules, rapport_texte}, soit exactement la réponse de /api/scan.
    """
    url = normaliser_url(url)

    debut = time.time()
    # Horodatage unique de l'audit, avec le fuseau local : il est repris
    # tel quel par l'interface, les exports .txt/.json et le rapport PDF.
    date_scan = datetime.now().astimezone().isoformat(timespec="seconds")

    # --- Récupération unique de la page (E42) -------------------------------
    reponse, parcours, erreur_page, remarque = None, [], None, None
    try:
        try:
            reponse, parcours = recuperer_page(url, timeout, autoriser_local)
        except ErreurRecuperation as e:
            if e.type_erreur != "certificat_refuse":
                raise
            # E36 : le certificat est refusé, mais le serveur répond. La page
            # est récupérée une seconde fois sans vérification, avec les mêmes
            # règles (redirections revalidées), pour analyser en-têtes et CMS ;
            # le module HTTPS classe l'erreur de certificat.
            reponse, parcours = recuperer_page(url, timeout, autoriser_local, verifier_certificat=False)
            remarque = REMARQUE_SANS_VERIFICATION
    except ErreurRecuperation as e:
        # Cible injoignable (nom introuvable, connexion refusée, délai
        # dépassé), ou refusée dès la première adresse : rien ne peut être
        # mesuré, le scan est impossible.
        if e.injoignable or not e.parcours:
            return _scan_impossible(url, e, debut, date_scan)
        # La cible a répondu, mais la page finale n'a pas pu être obtenue
        # (erreur TLS autre qu'un certificat refusé, redirection refusée,
        # trop de redirections) : audit partiel.
        parcours, erreur_page = e.parcours, e

    if reponse is not None:
        entetes = analyser_headers_reponse(reponse)
        cms = detecter_cms_reponse(reponse)
        url_finale = parcours[-1]
    else:
        message = "Page non récupérée : {}.".format(erreur_page.motif)
        entetes = _module_en_erreur(headers_analyzer.NOM_MODULE, message)
        cms = _module_en_erreur(cms_detector.NOM_MODULE, message)
        url_finale = None

    https = verifier_https(url, timeout=timeout, autoriser_local=autoriser_local)
    details_tls = https.get("details", {})
    hote_tls = details_tls.get("hote_tls")
    port_tls = details_tls.get("port_tls")
    hote_tls_lisible = "{} (port {})".format(hote_tls, port_tls) if hote_tls and port_tls else hote_tls

    resultats = [entetes, https, cms]

    duree = round(time.time() - debut, 2)
    score = calculer_score(resultats)
    rapport_texte = generer_rapport_texte(url, resultats, score, duree, date_scan,
                                          url_finale=url_finale, hote_tls=hote_tls_lisible,
                                          remarque=remarque)

    # On retire les en-têtes bruts complets : ils ne sont pas affichés et
    # peuvent être volumineux. En revanche « details » est conservé : il est
    # compact, et porte les champs exploités par la comparaison multi-sites
    # (CMS détecté, disponibilité HTTPS) ainsi que par le rapport PDF.
    for module in resultats:
        module.pop("headers_bruts", None)

    return {
        "url": url,
        "url_finale": url_finale,
        "redirections": parcours,
        "hote_tls": hote_tls,
        "statut": "complet" if score["complet"] else "partiel",
        "motif": None,
        "remarque": remarque,
        "version_outil": VERSION,
        "date_referentiel_cms": cms_detector.REFERENTIEL["date_releve"],
        "date_scan": date_scan,
        "duree": duree,
        "score": score,
        "modules": resultats,
        "rapport_texte": rapport_texte,
    }


def _scan_impossible(url, erreur, debut, date_scan):
    """Résultat d'un scan impossible (E15) : aucun point, aucune note."""
    duree = round(time.time() - debut, 2)
    score = {
        "points": None,
        "note": None,
        "decompte": {"CRITIQUE": 0, "AVERTISSEMENT": 0, "INFO": 0, "OK": 0},
        "complet": False,
        "modules_non_executes": [
            headers_analyzer.NOM_MODULE, https_checker.NOM_MODULE, cms_detector.NOM_MODULE],
    }
    return {
        "url": url,
        "url_finale": None,
        "redirections": erreur.parcours,
        "hote_tls": None,
        "statut": "impossible",
        "motif": erreur.motif,
        "remarque": None,
        "version_outil": VERSION,
        "date_referentiel_cms": cms_detector.REFERENTIEL["date_releve"],
        "date_scan": date_scan,
        "duree": duree,
        "score": score,
        "modules": [],
        "rapport_texte": generer_rapport_impossible(url, erreur.motif, duree, date_scan),
    }
