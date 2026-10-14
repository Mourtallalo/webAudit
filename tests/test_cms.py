"""
Tests du module CMS (remarques E27, E29, E28, E31, E30 ; constats C05, C06),
hors ligne : pages HTML de test dans tests/pages/.
"""

import json
import os

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import cms_detector
from cms_detector import detecter_cms_reponse, evaluer_version

PAGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
MENTION = "Référence des versions relevée le 14/10/2026"


def page(nom, generator=None, **entetes):
    with open(os.path.join(PAGES, nom), encoding="utf-8") as f:
        html = f.read()
    if generator is not None:
        html = html.replace("{generator}", generator)
    r = requests.Response()
    r.status_code = 200
    r.headers = CaseInsensitiveDict({k.replace("_", "-"): v for k, v in entetes.items()})
    r._content = html.encode("utf-8")
    r.encoding = "utf-8"
    return r


def observations(resultat):
    return {o["critere"]: (o["niveau"], o["message"]) for o in resultat["observations"]}


def avec_generator(contenu):
    return detecter_cms_reponse(page("gabarit_generator.html", generator=contenu))


# ---------------------------------------------------------------------------
# E28 : référentiel daté et sourcé
# ---------------------------------------------------------------------------

def test_referentiel_charge_depuis_le_fichier():
    chemin = os.path.join(os.path.dirname(PAGES), "..", "versions_reference.json")
    with open(chemin, encoding="utf-8") as f:
        assert cms_detector.REFERENTIEL == json.load(f)
    assert cms_detector.REFERENTIEL["date_releve"] == "2026-10-14"
    assert cms_detector.MENTION_REFERENTIEL == MENTION


def test_aucune_version_ecrite_en_dur():
    with open(cms_detector.__file__, encoding="utf-8") as f:
        source = f.read()
    for version in ("7.1.3", "11.4.9", "6.2.0", "9.2.0", "6.5", "10.2", "5.1", "8.1"):
        assert '"{}"'.format(version) not in source


def test_cle_fichiers_supprimee():
    # E30 : aucun fichier caractéristique n'est déclaré ni lu.
    assert not hasattr(cms_detector, "CMS_SIGNATURES")
    with open(cms_detector.__file__, encoding="utf-8") as f:
        assert '"fichiers"' not in f.read()


# ---------------------------------------------------------------------------
# E27 / E29 : identification et source de la version
# ---------------------------------------------------------------------------

def test_wordpress_version_pas_tiree_d_un_plugin():
    resultat = detecter_cms_reponse(page("wp_plugin_sans_generator.html"))
    assert resultat["details"]["cms"] == "WordPress"
    assert resultat["details"]["version"] is None  # ni 1.2.3 (plugin), ni 3.7.1 (jQuery), ni 2.0 (thème)
    assert observations(resultat)["Version du CMS"] == (
        "OK", "Version non divulguée (bonne pratique) : actualité non vérifiable. " + MENTION + ".")


def test_wordpress_version_des_ressources_du_coeur():
    resultat = detecter_cms_reponse(page("wp_wp_includes_ver.html"))
    assert resultat["details"]["version"] == "7.0.7"
    niveau, message = observations(resultat)["Version du CMS"]
    assert niveau == "AVERTISSEMENT"
    assert "paramètre ?ver= des ressources du cœur sous /wp-includes/ (confiance moyenne)" in message


@pytest.mark.parametrize("nom", ["sur_mesure_templates.html", "sur_mesure_themes.html", "indices_isoles.html"])
def test_aucun_cms_sur_un_site_sur_mesure(nom):
    resultat = detecter_cms_reponse(page(nom))
    assert resultat["details"]["cms"] is None
    assert observations(resultat) == {"Identification du CMS": (
        "OK", "Aucun CMS standard détecté. Le site utilise probablement un développement sur mesure.")}


@pytest.mark.parametrize("nom, cms", [
    ("drupal_signature.html", "Drupal"),
    ("joomla_signature.html", "Joomla"),
    ("prestashop_signature.html", "PrestaShop"),
])
def test_signatures_a_deux_indices(nom, cms):
    resultat = detecter_cms_reponse(page(nom))
    assert resultat["details"]["cms"] == cms
    assert len(resultat["details"]["indices"]) == 2


def test_drupal_par_en_tete_x_generator():
    r = page("sur_mesure_themes.html", X_Generator="Drupal 11 (https://www.drupal.org)")
    r._content = r._content.replace(b"/static/themes/sombre.css", b"/core/misc/drupal.js")
    assert detecter_cms_reponse(r)["details"]["cms"] == "Drupal"


# ---------------------------------------------------------------------------
# E31 / C05 / C06 : niveaux
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("generator, niveau, extrait", [
    ("WordPress 7.0.7", "AVERTISSEMENT", "WordPress 7.0.7 : version non à jour (référence : 7.1.3 ; source : "
                                         "https://wordpress.org/download/releases/"),
    ("WordPress 7.1.3", "OK", "WordPress 7.1.3 : à jour (référence : 7.1.3)."),
    ("WordPress 7.2.0", "OK", "plus récente que la référence (7.1.3) : référentiel à mettre à jour."),
    ("Drupal 10 (https://www.drupal.org)", "INFO", "Drupal 10 : version partielle : impossible de conclure."),
    ("Drupal 7 (http://drupal.org)", "CRITIQUE", "Drupal 7 : aucune branche 7 n'est maintenue d'après la source"),
    ("Drupal 9 (https://www.drupal.org)", "CRITIQUE", "aucune branche 9 n'est maintenue"),
    ("Drupal 11.2.5", "CRITIQUE", "Drupal 11.2.5 : la branche 11.2 ne figure pas parmi les branches "
                                  "maintenues (11.4, 11.3, 10.6) d'après la source (https://www.drupal.org/"),
    ("Drupal 11.4.9", "OK", "Drupal 11.4.9 : à jour (référence : branche 11.4, 11.4.9)."),
    ("Drupal 11.3.2", "AVERTISSEMENT", "version non à jour (référence : branche 11.3, 11.3.18"),
    ("Joomla! 6.1.4", "AVERTISSEMENT", "Joomla 6.1.4 : version non à jour (référence : branche 6, 6.2.0"),
    ("Joomla! 4.4.2", "AVERTISSEMENT", "Joomla 4.4.2 : version non à jour (référence : 6.2.0"),
    ("PrestaShop 9.1.3", "AVERTISSEMENT", "référence : branche 9.1, 9.1.5"),
])
def test_niveaux_de_version(generator, niveau, extrait):
    obtenu_niveau, message = observations(avec_generator(generator))["Version du CMS"]
    assert obtenu_niveau == niveau
    assert extrait in message
    assert MENTION in message
    assert "balise meta generator (confiance élevée)" in message
    assert "vulnérabilités connues" not in message


def test_joomla_generator_sans_version():
    resultat = avec_generator("Joomla! - Open Source Content Management")
    assert resultat["details"]["cms"] == "Joomla"
    assert observations(resultat)["Version du CMS"] == (
        "OK", "Version non divulguée (bonne pratique) : actualité non vérifiable. " + MENTION + ".")


def test_usage_d_un_cms_ne_coute_aucun_point():
    resultat = avec_generator("WordPress 7.1.3")
    assert [o["niveau"] for o in resultat["observations"]] == ["OK", "OK"]


def test_jamais_critique_sans_branches_maintenues():
    # Seul Drupal liste ses branches maintenues : pour les autres, au pire AVERTISSEMENT.
    assert evaluer_version("WordPress", "4.9.1")[0] == "AVERTISSEMENT"
    assert evaluer_version("PrestaShop", "1.7.8")[0] == "AVERTISSEMENT"
    assert evaluer_version("Joomla", "3")[0] == "INFO"
