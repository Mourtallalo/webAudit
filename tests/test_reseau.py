"""
Tests du filtre anti-SSRF, de la récupération de page et du scan
impossible (remarques E42, E38, E39, E40, E15, C18), hors ligne.

La résolution DNS est factice (conftest.py) ; les échanges HTTP se font
avec un serveur local lancé dans un thread.
"""

import json
import socket

import pytest

import app as application
import moteur
import scanner
from reseau import valider_cible, recuperer_page, ErreurRecuperation, MOTIF_NOM_INTROUVABLE


# ---------------------------------------------------------------------------
# valider_cible
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://172.16.0.5",
    "http://192.168.1.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://localtest.me",
    "http://169.254.169.254.nip.io",
    # Compléments : non spécifiée, multidiffusion, IPv6 privée et lien local,
    # IPv4 mappée en IPv6, partage d'adresses (CGNAT).
    "http://0.0.0.0",
    "http://224.0.0.1",
    "http://[fc00::1]",
    "http://[fe80::1]",
    "http://[::ffff:1.1.1.1]",
    "http://100.64.0.1",
])
def test_cibles_refusees(dns, url):
    dns["localtest.me"] = ["127.0.0.1"]
    dns["169.254.169.254.nip.io"] = ["169.254.169.254"]
    ok, motif = valider_cible(url)
    assert ok is False
    assert motif.startswith("adresse non publique refusée")


def test_nom_commencant_par_10_accepte_si_adresse_publique(dns):
    # E40 : aucun test sur le début du nom.
    dns["10.exemple.com"] = ["1.1.1.1"]
    assert valider_cible("https://10.exemple.com") == (True, "")


def test_une_seule_adresse_privee_suffit_a_refuser(dns):
    dns["mixte.test"] = ["1.1.1.1", "2606:4700:4700::1111", "10.0.0.1"]
    ok, motif = valider_cible("https://mixte.test")
    assert ok is False
    assert "10.0.0.1" in motif


def test_adresses_ipv4_et_ipv6_publiques_acceptees(dns):
    dns["public.test"] = ["1.1.1.1", "2606:4700:4700::1111"]
    assert valider_cible("https://public.test") == (True, "")


def test_nom_introuvable(dns):
    assert valider_cible("https://inexistant.test") == (False, MOTIF_NOM_INTROUVABLE)
    # Même motif quand les adresses locales sont autorisées.
    assert valider_cible("https://inexistant.test", autoriser_local=True) == (False, MOTIF_NOM_INTROUVABLE)


@pytest.mark.parametrize("url", ["ftp://exemple.com", "file:///etc/passwd", "https://"])
def test_schema_et_nom_d_hote_obligatoires(url):
    ok, _ = valider_cible(url)
    assert ok is False


def test_autoriser_local(dns):
    assert valider_cible("http://127.0.0.1", autoriser_local=True) == (True, "")


# ---------------------------------------------------------------------------
# recuperer_page : redirections suivies à la main et revalidées (E39)
# ---------------------------------------------------------------------------

def passer_par(monkeypatch, serveur):
    """
    Fait passer les requêtes HTTP par le serveur local, utilisé comme
    mandataire : le nom public n'est résolu que par le filtre, et la
    réponse vient quand même du serveur local.
    """
    for nom in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(nom, "http://127.0.0.1:{}".format(serveur.port))
    for nom in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(nom, raising=False)


def test_redirection_vers_adresse_locale_refusee(dns, serveur_local, monkeypatch):
    dns["public.test"] = ["1.1.1.1"]
    serveur = serveur_local({"*": (302, {"Location": "http://127.0.0.1:{port}/secret"}, b"")})
    passer_par(monkeypatch, serveur)

    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page("http://public.test/", timeout=5)

    assert erreur.value.type_erreur == "cible_refusee"
    assert erreur.value.motif.startswith("redirection refusée vers http://127.0.0.1:")
    assert erreur.value.parcours == ["http://public.test/"]
    assert erreur.value.injoignable is False
    # L'adresse locale n'a jamais été demandée.
    assert serveur.chemins_demandes == ["http://public.test/"]


def test_redirection_refusee_donne_un_audit_partiel(dns, serveur_local, monkeypatch):
    dns["public.test"] = ["1.1.1.1"]
    serveur = serveur_local({"*": (302, {"Location": "http://127.0.0.1:{port}/secret"}, b"")})
    passer_par(monkeypatch, serveur)
    monkeypatch.setattr(moteur, "verifier_https", lambda url, timeout=10, autoriser_local=False: {
        "module": "HTTPS / TLS", "statut": "succes", "message": "", "observations": [],
        "details": {"hote_tls": "public.test"}})

    resultat = moteur.lancer_scan("http://public.test/", timeout=5)

    assert resultat["statut"] == "partiel"
    assert resultat["score"]["note"] is None
    assert resultat["score"]["points"] == 100
    assert resultat["url_finale"] is None
    entetes, _, cms = resultat["modules"]
    assert entetes["statut"] == cms["statut"] == "erreur"
    assert "redirection refusée" in entetes["message"]


def test_redirections_suivies_en_local(dns, serveur_local):
    dns["site.test"] = ["127.0.0.1"]
    serveur = serveur_local({
        "/": (301, {"Location": "/fin"}, b""),
        "/fin": (200, {"X-Frame-Options": "DENY"}, b"<html></html>"),
    })
    url = "http://site.test:{}/".format(serveur.port)

    reponse, parcours = recuperer_page(url, timeout=5, autoriser_local=True)

    assert reponse.status_code == 200
    assert reponse.headers["X-Frame-Options"] == "DENY"
    assert parcours == [url, url + "fin"]
    assert reponse.request.headers["User-Agent"] == "WebAudit/1.0 (Audit de securite academique)"


def test_trop_de_redirections(dns, serveur_local):
    dns["boucle.test"] = ["127.0.0.1"]
    serveur = serveur_local({"/": (302, {"Location": "/"}, b"")})
    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page("http://boucle.test:{}/".format(serveur.port), timeout=5, autoriser_local=True)
    assert erreur.value.type_erreur == "trop_de_redirections"
    assert len(serveur.chemins_demandes) == 6  # la page + 5 redirections


def test_connexion_refusee(dns):
    dns["ferme.test"] = ["127.0.0.1"]
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # plus personne n'écoute sur ce port
    with pytest.raises(ErreurRecuperation) as erreur:
        recuperer_page("http://ferme.test:{}/".format(port), timeout=5, autoriser_local=True)
    assert erreur.value.type_erreur == "connexion_refusee"
    assert erreur.value.injoignable is True


def test_delai_depasse(dns):
    dns["muet.test"] = ["127.0.0.1"]
    muet = socket.socket()
    muet.bind(("127.0.0.1", 0))
    muet.listen(1)  # accepte la connexion mais ne répond jamais
    try:
        with pytest.raises(ErreurRecuperation) as erreur:
            recuperer_page("http://muet.test:{}/".format(muet.getsockname()[1]),
                           timeout=0.5, autoriser_local=True)
    finally:
        muet.close()
    assert erreur.value.type_erreur == "delai_depasse"
    assert erreur.value.injoignable is True


def test_scan_local_complet_page_recuperee_une_seule_fois(dns, serveur_local, monkeypatch):
    dns["site.test"] = ["127.0.0.1"]
    serveur = serveur_local({
        "/": (302, {"Location": "/accueil"}, b""),
        "/accueil": (200, {"Server": "factice"}, b"<html><body>bonjour</body></html>"),
    })
    monkeypatch.setattr(moteur, "verifier_https", lambda url, timeout=10, autoriser_local=False: {
        "module": "HTTPS / TLS", "statut": "succes", "message": "", "observations": [],
        "details": {"hote_tls": "site.test"}})
    url = "http://site.test:{}/".format(serveur.port)

    resultat = moteur.lancer_scan(url, timeout=5, autoriser_local=True)

    assert resultat["statut"] == "complet"
    assert resultat["url_finale"] == url + "accueil"
    assert resultat["redirections"] == [url, url + "accueil"]
    assert resultat["hote_tls"] == "site.test"
    # Une seule récupération de la page, même suivie d'une redirection (E42).
    assert serveur.chemins_demandes == ["/", "/accueil"]
    assert "URL analysée   : {}accueil".format(url) in resultat["rapport_texte"]


# ---------------------------------------------------------------------------
# Scan impossible (E15)
# ---------------------------------------------------------------------------

def verifier_impossible(resultat):
    assert resultat["statut"] == "impossible"
    assert resultat["motif"] == MOTIF_NOM_INTROUVABLE
    assert resultat["score"]["points"] is None
    assert resultat["score"]["note"] is None
    assert resultat["modules"] == []
    assert "SCAN IMPOSSIBLE : nom de domaine introuvable" in resultat["rapport_texte"]


def test_domaine_introuvable_moteur():
    verifier_impossible(moteur.lancer_scan("https://inexistant.test"))


def test_domaine_introuvable_interface_web():
    reponse = application.app.test_client().post("/api/scan", json={"autorisation": True, "url": "inexistant.test"})
    assert reponse.status_code == 200
    verifier_impossible(reponse.get_json())


def test_domaine_introuvable_ligne_de_commande(tmp_path, capsys):
    chemin = tmp_path / "r.json"
    with pytest.raises(SystemExit) as sortie:
        scanner.main(["--autorise", "inexistant.test", "--json", str(chemin)])
    assert sortie.value.code == 2
    verifier_impossible(json.loads(chemin.read_text(encoding="utf-8")))
    assert "Scan impossible : nom de domaine introuvable" in capsys.readouterr().err


def test_pas_de_pdf_pour_un_scan_impossible():
    resultat = moteur.lancer_scan("https://inexistant.test")
    reponse = application.app.test_client().post("/api/rapport-pdf", json=resultat)
    assert reponse.status_code == 400


# ---------------------------------------------------------------------------
# Filtre de l'interface web
# ---------------------------------------------------------------------------

def test_interface_web_refuse_une_cible_locale(dns):
    dns["localtest.me"] = ["127.0.0.1"]
    reponse = application.app.test_client().post("/api/scan", json={"autorisation": True, "url": "localtest.me"})
    assert reponse.status_code == 400
    assert "adresse non publique refusée" in reponse.get_json()["erreur"]


def test_ancien_filtre_par_prefixe_supprime():
    assert not hasattr(application, "url_valide")
