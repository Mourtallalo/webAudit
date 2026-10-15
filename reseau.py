"""
reseau.py
=========
Accès réseau partagé de WebAudit (remarques E42, E38, E39, E40, E15).

- valider_cible() : filtre anti-SSRF fondé sur les adresses réellement
  résolues, et non sur le début du nom d'hôte.
- recuperer_page() : l'unique requête GET de la page analysée, avec
  des redirections suivies à la main et revalidées une à une.

Limite connue : entre la validation DNS et la connexion, un nom peut
changer d'adresse (rebinding DNS). Le filtre réduit ce risque sans le
supprimer (voir README.md).

Auteur : Mourtalla LO
Mémoire de fin de Licence 3 Réseaux et Télécommunications - ESTM 2025-2026
"""

import socket
import ssl
import ipaddress
import warnings
from urllib.parse import urlparse, urljoin

import requests
import urllib3


# User-Agent historique du module d'en-têtes, désormais commun à toutes
# les requêtes HTTP du scanner.
USER_AGENT = "WebAudit/1.0 (Audit de securite academique)"

# Nombre maximal de redirections suivies pour une même page.
MAX_REDIRECTIONS = 5

MOTIF_NOM_INTROUVABLE = "nom de domaine introuvable"

# Types d'erreur pour lesquels la cible est considérée comme injoignable :
# le scan est alors « impossible » (aucun point, aucune note). Une erreur
# TLS n'en fait pas partie : la cible répond, et le module HTTPS sait
# classer le problème (E36, E35).
TYPES_INJOIGNABLE = ("nom_introuvable", "connexion_refusee", "delai_depasse")


class ErreurRecuperation(Exception):
    """
    Échec de la récupération d'une page.

    type_erreur : nom_introuvable, connexion_refusee, delai_depasse,
                  certificat_refuse, erreur_tls, cible_refusee,
                  trop_de_redirections,
                  erreur_requete.
    motif       : explication lisible, en français.
    parcours    : URL déjà demandées avant l'échec.
    """

    def __init__(self, type_erreur, motif, parcours=None):
        super().__init__(motif)
        self.type_erreur = type_erreur
        self.motif = motif
        self.parcours = list(parcours or [])

    @property
    def injoignable(self):
        return self.type_erreur in TYPES_INJOIGNABLE


def forme_url_valide(url):
    """Contrôle de forme seul (sans résolution DNS) : schéma http(s) et nom d'hôte."""
    try:
        analyse = urlparse(url)
        return analyse.scheme in ("http", "https") and bool(analyse.hostname)
    except ValueError:
        return False


def adresse_publique(adresse):
    """True si l'adresse IP (objet ipaddress) est publique et joignable sans risque."""
    if isinstance(adresse, ipaddress.IPv6Address) and adresse.ipv4_mapped is not None:
        # ::ffff:a.b.c.d : refusée dans tous les cas, quelle que soit l'IPv4 incluse.
        return False
    return adresse.is_global and not (
        adresse.is_private
        or adresse.is_loopback
        or adresse.is_link_local
        or adresse.is_multicast
        or adresse.is_reserved
        or adresse.is_unspecified
    )


def _resoudre(hote, port):
    """Toutes les adresses IPv4 et IPv6 du nom d'hôte (lève ErreurRecuperation)."""
    try:
        infos = socket.getaddrinfo(hote, port, 0, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise ErreurRecuperation("nom_introuvable", MOTIF_NOM_INTROUVABLE)
    adresses = []
    for info in infos:
        # Une adresse IPv6 peut porter un identifiant de zone (« %eth0 »).
        texte = str(info[4][0]).split("%")[0]
        adresse = ipaddress.ip_address(texte)
        if adresse not in adresses:
            adresses.append(adresse)
    if not adresses:
        raise ErreurRecuperation("nom_introuvable", MOTIF_NOM_INTROUVABLE)
    return adresses


def _verifier_cible(url, autoriser_local):
    """Lève ErreurRecuperation si la cible ne peut pas être interrogée."""
    try:
        analyse = urlparse(url)
        port = analyse.port
    except ValueError:
        raise ErreurRecuperation("cible_refusee", "URL invalide : {}".format(url))
    if analyse.scheme not in ("http", "https"):
        raise ErreurRecuperation("cible_refusee", "schéma non autorisé (http ou https uniquement)")
    if not analyse.hostname:
        raise ErreurRecuperation("cible_refusee", "nom d'hôte manquant")

    if port is None:
        port = 443 if analyse.scheme == "https" else 80

    # La résolution est faite même quand les adresses locales sont
    # autorisées : un nom inexistant doit toujours donner le même motif.
    adresses = _resoudre(analyse.hostname, port)
    if autoriser_local:
        return
    for adresse in adresses:
        if not adresse_publique(adresse):
            raise ErreurRecuperation(
                "cible_refusee",
                "adresse non publique refusée : {} résout vers {}".format(analyse.hostname, adresse))


def valider_cible(url, autoriser_local=False):
    """
    Vérifie qu'une URL peut être auditée.

    Exige un schéma http ou https et un nom d'hôte, résout ce nom
    (IPv4 et IPv6) et refuse la cible si UNE SEULE des adresses n'est
    pas publique, sauf si autoriser_local vaut True.

    Retour
    ------
    tuple (ok, motif) : motif est une chaîne vide quand ok vaut True.
    """
    try:
        _verifier_cible(url, autoriser_local)
    except ErreurRecuperation as e:
        return False, e.motif
    return True, ""


def _certificat_refuse(erreur):
    """True si l'erreur TLS vient du refus du certificat (et non de la poignée de main)."""
    vues = set()
    courante = erreur
    while courante is not None and id(courante) not in vues:
        vues.add(id(courante))
        if isinstance(courante, ssl.SSLCertVerificationError):
            return True
        # requests et urllib3 emballent l'erreur d'origine : on suit la chaîne.
        suivantes = [courante.__cause__, courante.__context__] + [
            a for a in getattr(courante, "args", ()) if isinstance(a, BaseException)]
        suivantes += [getattr(courante, "reason", None)]
        courante = next((s for s in suivantes if isinstance(s, BaseException) and id(s) not in vues), None)
    return "CERTIFICATE_VERIFY_FAILED" in str(erreur).upper()


def recuperer_page(url, timeout, autoriser_local=False, verifier_certificat=True):
    """
    Récupère la page par une requête GET, en suivant les redirections à la main.

    Chaque adresse (la première comme chaque redirection) est validée par
    valider_cible avant d'être demandée ; MAX_REDIRECTIONS au plus.

    verifier_certificat=False désactive la vérification du certificat
    (verify=False) : le moteur ne s'en sert qu'après un refus du
    certificat, pour analyser quand même la page (E36).

    Retour
    ------
    tuple (réponse finale requests.Response, liste des URL parcourues).
    Lève ErreurRecuperation en cas d'échec.
    """
    parcours = []
    courante = url

    for _ in range(MAX_REDIRECTIONS + 1):
        try:
            _verifier_cible(courante, autoriser_local)
        except ErreurRecuperation as e:
            if parcours and e.type_erreur == "cible_refusee":
                e.motif = "redirection refusée vers {} : {}".format(courante, e.motif)
            e.parcours = list(parcours)
            raise e
        parcours.append(courante)

        try:
            with warnings.catch_warnings():
                # Sans vérification, urllib3 avertit à chaque requête :
                # l'avertissement est neutralisé ici seulement, le moteur
                # signalant lui-même la situation dans le rapport.
                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                reponse = requests.get(
                    courante,
                    timeout=timeout,
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=False,
                    verify=verifier_certificat,
                )
        except requests.exceptions.SSLError as e:
            if _certificat_refuse(e):
                raise ErreurRecuperation(
                    "certificat_refuse", "certificat refusé : {}".format(e), parcours)
            raise ErreurRecuperation(
                "erreur_tls", "erreur TLS : impossible d'établir une connexion sécurisée ({})".format(e),
                parcours)
        except requests.exceptions.Timeout:
            raise ErreurRecuperation(
                "delai_depasse", "délai d'attente dépassé ({} s) : la cible ne répond pas".format(timeout),
                parcours)
        except requests.exceptions.ConnectionError:
            raise ErreurRecuperation(
                "connexion_refusee", "connexion refusée ou impossible : la cible est injoignable",
                parcours)
        except requests.exceptions.RequestException as e:
            raise ErreurRecuperation("erreur_requete", "erreur lors de la requête : {}".format(e), parcours)

        if reponse.is_redirect:
            courante = urljoin(courante, reponse.headers["location"])
            reponse.close()
            continue
        return reponse, parcours

    raise ErreurRecuperation(
        "trop_de_redirections", "plus de {} redirections".format(MAX_REDIRECTIONS), parcours)
