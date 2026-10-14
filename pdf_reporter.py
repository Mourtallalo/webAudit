"""
pdf_reporter.py
===============
Generation du rapport d'audit au format PDF.

Ce module reprend les resultats produits par les modules d'analyse et
les met en page dans un document imprimable : en-tete, note globale,
detail par categorie, puis recommandations chiffrees.

Il ne realise aucune analyse : il ne fait que mettre en forme ce que
reporter.py a deja calcule.

Dependance : reportlab (voir requirements.txt).

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

import textwrap
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from fiches import FICHES, NOMS_MODULES
from version import VERSION

# ---------------------------------------------------------------------------
# Palette : les memes teintes que l'interface web, en theme clair.
# Les contrastes ont ete verifies au niveau AA sur fond papier.
# ---------------------------------------------------------------------------
ENCRE = colors.HexColor("#15140F")
ENCRE_DOUCE = colors.HexColor("#56524A")
PAPIER = colors.HexColor("#FBF9F3")
PAPIER_2 = colors.HexColor("#F4F1E7")
FILET = colors.HexColor("#E2DCCC")
SCEAU = colors.HexColor("#7A5A1E")

SEVERITES = {
    "CRITIQUE": {
        "couleur": colors.HexColor("#8E1710"),
        "fond": colors.HexColor("#FBEAE8"),
        "glyphe": "!",
        "libelle": "CRITIQUE",
    },
    "AVERTISSEMENT": {
        "couleur": colors.HexColor("#7E570A"),
        "fond": colors.HexColor("#FAF2DE"),
        "glyphe": "~",
        "libelle": "À SURVEILLER",
    },
    "INFO": {
        "couleur": colors.HexColor("#1D60AB"),
        "fond": colors.HexColor("#E9F0FA"),
        "glyphe": "i",
        "libelle": "INFO",
    },
    "OK": {
        "couleur": colors.HexColor("#1F6E3C"),
        "fond": colors.HexColor("#E6F3EA"),
        "glyphe": "+",
        "libelle": "CONFORME",
    },
}

# Marges et largeur utile, utilisees pour caler les tableaux.
MARGE = 18 * mm
LARGEUR_UTILE = A4[0] - 2 * MARGE

# Ordre d'affichage : le plus grave en premier.
RANG = {"CRITIQUE": 0, "AVERTISSEMENT": 1, "INFO": 2, "OK": 3}


# ---------------------------------------------------------------------------
# Styles de paragraphe
# ---------------------------------------------------------------------------

def _style(nom, taille, couleur=ENCRE, gras=False, interligne=None, espace_apres=0,
           espace_avant=0, gauche=0):
    return ParagraphStyle(
        nom,
        fontName="Helvetica-Bold" if gras else "Helvetica",
        fontSize=taille,
        leading=interligne or taille * 1.45,
        textColor=couleur,
        spaceAfter=espace_apres,
        spaceBefore=espace_avant,
        leftIndent=gauche,
        alignment=TA_LEFT,
    )


S_TITRE = _style("titre", 20, ENCRE, gras=True, interligne=24)
S_SURTITRE = _style("surtitre", 7.5, SCEAU, gras=True, espace_apres=4)
S_CIBLE = _style("cible", 13, ENCRE, gras=True, espace_apres=2)
S_META = _style("meta", 8.5, ENCRE_DOUCE, espace_apres=2)
S_SECTION = _style("section", 12, ENCRE, gras=True, espace_apres=6, espace_avant=14)
S_SOUS_SECTION = _style("sous_section", 9.5, ENCRE, gras=True, espace_apres=3)
S_CORPS = _style("corps", 8.8, ENCRE, interligne=12.5, espace_apres=3)
S_CORPS_DOUX = _style("corps_doux", 8.8, ENCRE_DOUCE, interligne=12.5, espace_apres=3)
S_ETIQUETTE = _style("etiquette", 6.8, ENCRE_DOUCE, gras=True, espace_apres=2)
S_CODE = ParagraphStyle(
    "code",
    fontName="Courier",
    fontSize=7.4,
    leading=10.4,
    textColor=colors.HexColor("#23211A"),
    leftIndent=6,
    rightIndent=6,
    spaceBefore=3,
    spaceAfter=3,
)


def _p(texte, style):
    """Paragraphe dont le texte est echappe : les donnees viennent du scan."""
    return Paragraph(escape(str(texte or "")), style)


# ---------------------------------------------------------------------------
# Le tampon : reprend le motif circulaire de l'interface web.
# ---------------------------------------------------------------------------

class Tampon(Flowable):
    """Pastille circulaire portant la note globale et les points."""

    def __init__(self, note, points, couleur, cote=74):
        Flowable.__init__(self)
        self.note = note
        self.points = points
        self.couleur = couleur
        self.width = cote
        self.height = cote

    def draw(self):
        c = self.canv
        centre = self.width / 2.0
        rayon = self.width / 2.0 - 1

        # Double cercle : le bord du tampon.
        c.setStrokeColor(self.couleur)
        c.setLineWidth(1.6)
        c.circle(centre, centre, rayon, stroke=1, fill=0)
        c.setLineWidth(0.5)
        c.circle(centre, centre, rayon - 4, stroke=1, fill=0)

        c.setFillColor(self.couleur)
        c.setFont("Helvetica-Bold", 26)
        c.drawCentredString(centre, centre + 1, str(self.note))

        c.setFillColor(ENCRE_DOUCE)
        c.setFont("Helvetica", 7.5)
        c.drawCentredString(centre, centre - 12, "{}/100".format(self.points))


def _severite_de_la_note(note):
    """
    A+/A/B : conforme - C/D : a surveiller - E/F : critique.

    reporter.py ne pose aucune lettre quand l'audit est partiel : le
    resultat est alors neutre, et None signale qu'aucune couleur de
    verdict ne doit etre appliquee.
    """
    if not note:
        return None
    if note in ("A+", "A", "B"):
        return "OK"
    if note in ("C", "D"):
        return "AVERTISSEMENT"
    return "CRITIQUE"


# ---------------------------------------------------------------------------
# Blocs du document
# ---------------------------------------------------------------------------

def _entete(url, score, duree, moment, url_finale=None, version_outil=None, date_referentiel=None):
    """Bandeau de tete : cible, date, note globale et decompte."""
    hote = str(url or "").replace("https://", "").replace("http://", "")
    decompte = score.get("decompte", {})
    severite = _severite_de_la_note(score.get("note"))
    couleur = SEVERITES[severite]["couleur"] if severite else ENCRE_DOUCE

    identite = [
        _p("RAPPORT D'AUDIT DE SÉCURITÉ", S_SURTITRE),
        _p(hote, S_TITRE),
        Spacer(1, 6),
        _p("Date de l'audit : {}".format(moment.strftime("%d/%m/%Y à %H:%M")), S_META),
        _p("Durée du scan : {} secondes".format(duree), S_META),
        _p("URL analysée : {}".format(url_finale or "non indiquée"), S_META),
        _p("Outil : WebAudit {} — analyse passive".format(version_outil or VERSION), S_META),
    ]
    if date_referentiel:
        try:
            date_lisible = datetime.fromisoformat(str(date_referentiel)).strftime("%d/%m/%Y")
        except ValueError:
            date_lisible = str(date_referentiel)
        identite.append(_p("Versions CMS : référence relevée le {}".format(date_lisible), S_META))

    bandeau = Table(
        [[identite, Tampon(score.get("note") or "—", score.get("points", 0), couleur)]],
        colWidths=[LARGEUR_UTILE - 82, 82],
    )
    bandeau.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    # Ligne de decompte par niveau de gravite.
    cellules, styles = [], [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, FILET),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, FILET),
    ]
    for i, niveau in enumerate(["CRITIQUE", "AVERTISSEMENT", "INFO", "OK"]):
        info = SEVERITES[niveau]
        nombre = decompte.get(niveau, 0)
        cellules.append(Paragraph(
            '<font size="13"><b>{}</b></font>  '
            '<font size="7.5" color="{}">[{}] {}</font>'.format(
                nombre, info["couleur"].hexval().replace("0x", "#"),
                info["glyphe"], info["libelle"]),
            S_CORPS))
        styles.append(("BACKGROUND", (i, 0), (i, 0), info["fond"]))

    tableau_decompte = Table([cellules], colWidths=[LARGEUR_UTILE / 4.0] * 4)
    tableau_decompte.setStyle(TableStyle(styles))

    blocs = [bandeau, Spacer(1, 14), tableau_decompte]

    # Un audit partiel se signale juste sous le score, pas en note de
    # bas de page : la note ne porte alors que sur ce qui a abouti.
    if not score.get("complet", True):
        avertissement = SEVERITES["AVERTISSEMENT"]
        manquants = ", ".join(
            NOMS_MODULES.get(m, m) for m in score.get("modules_non_executes", []))

        encart = Table([[Paragraph(
            '<b>Audit partiel.</b> Le score ne porte que sur les contrôles qui ont '
            'abouti : {} n\'a pas répondu dans le délai imparti. La note ne vaut donc '
            'pas quitus — relancez l\'audit avant de conclure.'.format(escape(manquants)),
            S_CORPS)]], colWidths=[LARGEUR_UTILE])
        encart.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), avertissement["fond"]),
            ("BOX", (0, 0), (-1, -1), 0.8, avertissement["couleur"]),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ]))
        blocs.extend([Spacer(1, 10), encart])

    return blocs


def _tableau_module(module):
    """Tableau recapitulatif des observations d'un module."""
    lignes = [[
        _p("Gravité", S_ETIQUETTE),
        _p("Contrôle", S_ETIQUETTE),
        _p("Observation", S_ETIQUETTE),
    ]]
    styles = [
        ("BACKGROUND", (0, 0), (-1, 0), PAPIER_2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, FILET),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, FILET),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]

    observations = sorted(
        module.get("observations", []),
        key=lambda o: RANG.get(o.get("niveau", "INFO"), 2),
    )

    for i, obs in enumerate(observations, start=1):
        niveau = obs.get("niveau", "INFO")
        info = SEVERITES.get(niveau, SEVERITES["INFO"])
        libelle = obs.get("header") or obs.get("critere") or "Observation"

        lignes.append([
            Paragraph(
                '<font color="{}" size="7"><b>[{}] {}</b></font>'.format(
                    info["couleur"].hexval().replace("0x", "#"),
                    info["glyphe"], info["libelle"]),
                S_CORPS),
            _p(libelle, S_CORPS),
            _p(obs.get("message", ""), S_CORPS_DOUX),
        ])
        styles.append(("BACKGROUND", (0, i), (0, i), info["fond"]))

    # 90 pt pour la gravite : assez pour que "[~] À SURVEILLER" tienne
    # sur une seule ligne et que la colonne garde une hauteur reguliere.
    tableau = Table(lignes, colWidths=[90, 122, LARGEUR_UTILE - 212], repeatRows=1)
    tableau.setStyle(TableStyle(styles))
    return tableau


def _bloc_code(code):
    """Encadre un extrait de configuration, replie pour tenir dans la page."""
    lignes = []
    for ligne in str(code).split("\n"):
        # Courier 7.4 pt : environ 95 caracteres dans la largeur utile.
        lignes.extend(textwrap.wrap(ligne, width=95, subsequent_indent="    ",
                                    break_long_words=True, break_on_hyphens=False)
                      or [""])

    tableau = Table([[Paragraph(escape("\n".join(lignes)).replace("\n", "<br/>"), S_CODE)]],
                    colWidths=[LARGEUR_UTILE])
    tableau.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PAPIER_2),
        ("BOX", (0, 0), (-1, -1), 0.5, FILET),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tableau


def _recommandation(obs, numero):
    """Fiche de correction pour une observation non conforme."""
    libelle = obs.get("header") or obs.get("critere") or "Observation"
    fiche = FICHES.get(libelle)
    if not fiche:
        return None

    niveau = obs.get("niveau", "INFO")
    info = SEVERITES.get(niveau, SEVERITES["INFO"])

    blocs = [
        Paragraph(
            '{}. {} <font size="7" color="{}">[{}] {}</font>'.format(
                numero, escape(libelle),
                info["couleur"].hexval().replace("0x", "#"),
                info["glyphe"], info["libelle"]),
            S_SOUS_SECTION),
    ]
    if fiche.get("adapter"):
        blocs += [_p("À ADAPTER", S_ETIQUETTE), _p(fiche["adapter"], S_CORPS_DOUX)]
    blocs += [
        _p("CE QUE C'EST", S_ETIQUETTE),
        _p(fiche.get("quoi", ""), S_CORPS),
        _p("LE RISQUE", S_ETIQUETTE),
        _p(fiche.get("risque", ""), S_CORPS_DOUX),
    ]

    for correctif in fiche.get("fix", []):
        blocs.append(_p("CORRECTIF — {}".format(correctif.get("label", "")).upper(), S_ETIQUETTE))
        blocs.append(_bloc_code(correctif.get("code", "")))

    if fiche.get("apres"):
        blocs.append(_p("Puis rechargez le service : {}".format(fiche["apres"]), S_CORPS_DOUX))

    if fiche.get("note"):
        blocs.append(_p("Bon à savoir : {}".format(fiche["note"]), S_CORPS_DOUX))

    blocs.append(Spacer(1, 10))
    # KeepTogether evite qu'un correctif soit coupe entre deux pages.
    return KeepTogether(blocs)


def _habillage(canevas, doc):
    """Filet de tete et pied de page, repetes sur chaque page."""
    canevas.saveState()

    canevas.setStrokeColor(FILET)
    canevas.setLineWidth(0.5)
    canevas.line(MARGE, A4[1] - MARGE + 10, A4[0] - MARGE, A4[1] - MARGE + 10)

    canevas.setFont("Helvetica-Bold", 7)
    canevas.setFillColor(SCEAU)
    canevas.drawString(MARGE, A4[1] - MARGE + 15, "WebAudit")

    canevas.setFont("Helvetica", 6.5)
    canevas.setFillColor(ENCRE_DOUCE)
    canevas.drawRightString(A4[0] - MARGE, A4[1] - MARGE + 15,
                            "Rapport d'audit de sécurité — analyse passive")

    canevas.line(MARGE, MARGE - 6, A4[0] - MARGE, MARGE - 6)
    canevas.setFont("Helvetica", 6.2)
    canevas.drawString(
        MARGE, MARGE - 16,
        "Outil académique — mémoire L3 Réseaux et Télécommunications, ESTM 2025-2026. "
        "Audit passif, sur cible autorisée.")
    canevas.drawRightString(A4[0] - MARGE, MARGE - 16, "Page {}".format(doc.page))

    canevas.restoreState()


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------

def generer_rapport_pdf(url, modules, score, duree, date_scan=None, url_finale=None,
                        version_outil=None, date_referentiel=None):
    """
    Construit le rapport PDF et retourne son contenu binaire.

    Parametres
    ----------
    url : str      adresse auditee
    modules : list resultats renvoyes par les modules d'analyse
    score : dict   {"points", "note", "decompte"}
    duree : float  duree du scan en secondes
    date_scan : str  horodatage ISO de l'audit (a defaut : maintenant)
    url_finale : str     URL finale analysée après les redirections
    version_outil : str  version de WebAudit qui a produit le scan
    date_referentiel : str  date ISO du référentiel des versions CMS

    Retour
    ------
    bytes : le PDF pret a etre envoye au navigateur.
    """
    # La date vient du client : une valeur absente ou illisible ne doit pas
    # empecher la mise en page, on retombe alors sur l'heure courante.
    try:
        moment = datetime.fromisoformat(str(date_scan))
    except (TypeError, ValueError):
        moment = datetime.now()

    tampon = BytesIO()
    doc = SimpleDocTemplate(
        tampon,
        pagesize=A4,
        leftMargin=MARGE, rightMargin=MARGE,
        topMargin=MARGE, bottomMargin=MARGE,
        title="Rapport WebAudit — {}".format(url),
        author="WebAudit",
        subject="Audit de sécurité web",
    )

    histoire = []
    histoire.extend(_entete(url, score, duree, moment, url_finale, version_outil, date_referentiel))

    # --- Detail par categorie ----------------------------------------------
    histoire.append(_p("Détail par catégorie", S_SECTION))

    for module in modules:
        nom = NOMS_MODULES.get(module.get("module"), module.get("module", "Module"))
        histoire.append(_p(nom, S_SOUS_SECTION))

        if module.get("statut") == "erreur":
            histoire.append(_p("Module non exécuté : {}".format(module.get("message", "")),
                               S_CORPS_DOUX))
        else:
            histoire.append(_tableau_module(module))
        histoire.append(Spacer(1, 8))

    # --- Recommandations ----------------------------------------------------
    a_corriger = []
    for module in modules:
        for obs in module.get("observations", []):
            if obs.get("niveau") != "OK":
                a_corriger.append(obs)
    a_corriger.sort(key=lambda o: RANG.get(o.get("niveau", "INFO"), 2))

    histoire.append(PageBreak())
    histoire.append(_p("Recommandations", S_SECTION))

    if not a_corriger:
        histoire.append(_p(
            "Aucun point à corriger : tous les contrôles effectués sont conformes. "
            "Ce résultat ne couvre que les trois familles analysées par WebAudit "
            "(en-têtes HTTP, HTTPS/TLS, CMS) et ne constitue pas un audit exhaustif.",
            S_CORPS))
    else:
        histoire.append(_p(
            "Les points ci-dessous sont classés du plus grave au moins grave. "
            "Les commandes sont données pour Nginx et Apache : adaptez le nom de "
            "domaine et vérifiez la configuration avant de recharger le service.",
            S_CORPS_DOUX))
        histoire.append(Spacer(1, 8))

        numero = 1
        for obs in a_corriger:
            bloc = _recommandation(obs, numero)
            if bloc is not None:
                histoire.append(bloc)
                numero += 1

    doc.build(histoire, onFirstPage=_habillage, onLaterPages=_habillage)
    return tampon.getvalue()
