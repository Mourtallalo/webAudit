/**
 * script.js
 * =========
 * Page d'audit : validation du champ, progression du scan, rendu du
 * rapport, telechargements.
 *
 * Ce fichier ne contient aucune logique d'analyse : il se contente
 * d'afficher ce que renvoie /api/scan. Les briques partagees avec la
 * page de comparaison sont dans commun.js.
 *
 * Auteur : Mourtalla LO
 * Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
 */

"use strict";

/* ═══════════════════════════════════════════════════════════════
   1. Base de connaissances
   Elle est produite par fiches.py et injectee dans la page par Flask :
   l'interface et le rapport PDF partagent ainsi la meme source.
   ═══════════════════════════════════════════════════════════════ */

const FICHES = JSON.parse($("fiches-data").textContent);

const ETAPES = [
  { cle: "headers", texte: "Analyse des en-têtes…" },
  { cle: "https", texte: "Vérification HTTPS…" },
  { cle: "cms", texte: "Détection du CMS…" },
];

// Perimetre du cercle de la jauge (rayon 62), identique au CSS.
const PERIMETRE_JAUGE = 389.56;

/* ═══════════════════════════════════════════════════════════════
   2. References DOM
   ═══════════════════════════════════════════════════════════════ */

const sections = {
  hero: $("hero-section"),
  loading: $("loading-section"),
  error: $("error-section"),
  results: $("results-section"),
};

const form = $("scan-form");
const urlInput = $("url-input");
const scanBtn = $("scan-btn");
const caseAutorisation = $("autorisation");

// E26 : le bouton reste désactivé tant que la case n'est pas cochée.
function majBoutonScan() {
  scanBtn.disabled = !caseAutorisation.checked;
}
caseAutorisation.addEventListener("change", majBoutonScan);
// Le navigateur peut restaurer l'état de la case au rechargement.
majBoutonScan();
const inputError = $("input-error");
const inputHint = $("input-hint");

const progress = $("progress");
const progressBar = $("progress-bar");
const loadingUrl = $("loading-url");
const loadingStatus = $("loading-status");

const errorText = $("error-text");

const stamp = $("stamp");
const gaugeFill = $("gauge-fill");
const modulesContainer = $("modules-container");

let dernierRapport = null;
let champTouche = false;

/* ═══════════════════════════════════════════════════════════════
   3. Navigation entre ecrans
   ═══════════════════════════════════════════════════════════════ */

function afficher(nom) {
  Object.entries(sections).forEach(([cle, section]) => {
    section.hidden = cle !== nom;
  });
}

/* ═══════════════════════════════════════════════════════════════
   4. Validation du champ URL
   ═══════════════════════════════════════════════════════════════ */

function afficherErreurChamp(message) {
  if (message) {
    inputError.textContent = message;
    inputError.hidden = false;
    urlInput.setAttribute("aria-invalid", "true");
    urlInput.setAttribute("aria-describedby", "input-error");
    inputHint.hidden = true;
  } else {
    inputError.hidden = true;
    inputError.textContent = "";
    urlInput.removeAttribute("aria-invalid");
    urlInput.setAttribute("aria-describedby", "input-hint");
    inputHint.hidden = false;
  }
}

urlInput.addEventListener("input", () => {
  // On ne signale une erreur qu'apres une premiere tentative, pour ne
  // pas rougir le champ des la premiere lettre tapee.
  if (!champTouche) return;
  afficherErreurChamp(validerUrl(urlInput.value));
});

urlInput.addEventListener("blur", () => {
  if (urlInput.value.trim()) {
    champTouche = true;
    afficherErreurChamp(validerUrl(urlInput.value));
  }
});

/* ═══════════════════════════════════════════════════════════════
   5. Progression du scan
   ═══════════════════════════════════════════════════════════════ */

const etapeEl = (cle) => document.querySelector('.step[data-step="' + cle + '"]');

function poserProgression(pourcent) {
  const valeur = Math.round(pourcent);
  progressBar.style.width = valeur + "%";
  progress.setAttribute("aria-valuenow", String(valeur));
}

function reinitialiserEtapes() {
  document.querySelectorAll(".step").forEach((el) => {
    el.classList.remove("is-active", "is-done");
  });
  poserProgression(0);
}

async function animerEtapes() {
  // L'animation tourne en parallele de l'appel reseau : elle donne un
  // repere de progression meme quand le scan repond en une seconde.
  const total = ETAPES.length + 1; // les trois modules, puis la compilation

  for (let i = 0; i < ETAPES.length; i++) {
    const etape = ETAPES[i];
    const el = etapeEl(etape.cle);

    el.classList.add("is-active");
    loadingStatus.textContent = etape.texte;

    await pause(640);

    el.classList.remove("is-active");
    el.classList.add("is-done");
    poserProgression(((i + 1) / total) * 100);
  }

  // Derniere etape : elle reste active tant que le serveur n'a pas
  // repondu. Un scan lent (certificat injoignable, redirection longue)
  // peut depasser dix secondes ; sans ce repere, l'ecran semblerait fige.
  etapeEl("rapport").classList.add("is-active");
  loadingStatus.textContent = "Compilation du rapport…";
  poserProgression(92);
}

function terminerCompilation() {
  const el = etapeEl("rapport");
  el.classList.remove("is-active");
  el.classList.add("is-done");
  poserProgression(100);
}

/* ═══════════════════════════════════════════════════════════════
   6. Rendu : tampon et jauge
   ═══════════════════════════════════════════════════════════════ */

const COULEURS_JAUGE = {
  OK: { trait: "var(--ok)", piste: "var(--ok-bg)" },
  AVERTISSEMENT: { trait: "var(--warn)", piste: "var(--warn-bg)" },
  CRITIQUE: { trait: "var(--crit)", piste: "var(--crit-bg)" },
  // Audit partiel : aucune note attribuee, donc aucune couleur de verdict.
  NEUTRE: { trait: "var(--ink-2)", piste: "var(--paper-2)" },
};

function poserTampon(score) {
  const severite = severiteDeLaNote(score.note);
  const couleurs = COULEURS_JAUGE[severite];

  stamp.style.setProperty("--gauge-fill", couleurs.trait);
  stamp.style.setProperty("--gauge-track", couleurs.piste);
  stamp.style.setProperty("--grade-color", couleurs.trait);

  const lettre = $("grade-letter");
  lettre.textContent = noteAffichee(score.note);
  lettre.classList.toggle("is-absente", !score.note);

  // Remise a zero de la jauge, puis remplissage a la valeur finale.
  gaugeFill.style.transition = "none";
  gaugeFill.style.strokeDashoffset = String(PERIMETRE_JAUGE);
  void gaugeFill.getBoundingClientRect();
  gaugeFill.style.transition = "";

  const restant = PERIMETRE_JAUGE * (1 - Math.max(0, Math.min(100, score.points)) / 100);
  requestAnimationFrame(() => {
    gaugeFill.style.strokeDashoffset = String(restant);
  });

  // Relance l'animation de tampon a chaque nouveau rapport.
  stamp.classList.remove("is-stamped");
  void stamp.getBoundingClientRect();
  stamp.classList.add("is-stamped");

  animerCompteur($("result-points"), score.points, 900);
}

/* ═══════════════════════════════════════════════════════════════
   7. Rendu : observations
   ═══════════════════════════════════════════════════════════════ */

function construirePastille(niveau) {
  const badge = creer("span", "sev-badge");

  const glyphe = creer("span", "sev-glyph");
  glyphe.setAttribute("data-glyph", GLYPHES[niveau] || "?");
  glyphe.setAttribute("aria-hidden", "true");
  badge.appendChild(glyphe);

  // Le libelle textuel accompagne toujours la couleur, pour que le
  // niveau reste lisible sans percevoir la teinte.
  badge.appendChild(document.createTextNode(LIBELLES[niveau] || niveau));
  return badge;
}

function construireCorrectif(fix, apres) {
  const bloc = creer("div", "fix");

  const tete = creer("div", "fix-head");
  tete.appendChild(creer("span", "fix-label", "Correctif — " + fix.label));

  const bouton = creer("button", "copy-btn");
  bouton.type = "button";
  bouton.innerHTML =
    '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
    '<rect x="9" y="9" width="11" height="11" rx="2"/>' +
    '<path d="M15 5.5A1.5 1.5 0 0 0 13.5 4H5.5A1.5 1.5 0 0 0 4 5.5v8A1.5 1.5 0 0 0 5.5 15"/>' +
    "</svg><span>Copier</span>";

  const aCopier = apres ? fix.code + "\n\n# puis :\n" + apres : fix.code;
  bouton.addEventListener("click", () => copier(aCopier, bouton, fix.label));
  tete.appendChild(bouton);
  bloc.appendChild(tete);

  const pre = creer("pre");
  pre.appendChild(creer("code", null, fix.code));
  bloc.appendChild(pre);

  return bloc;
}

function construireDetail(fiche) {
  const detail = creer("div", "obs-detail");

  const lignes = [
    { kind: "adapter", tag: "À adapter", texte: fiche.adapter },
    { kind: "quoi", tag: "Ce que c'est", texte: fiche.quoi },
    { kind: "risque", tag: "Le risque", texte: fiche.risque },
  ];

  lignes.forEach((ligne) => {
    if (!ligne.texte) return;
    const row = creer("div", "detail-row");
    row.setAttribute("data-kind", ligne.kind);
    row.appendChild(creer("span", "detail-tag", ligne.tag));
    row.appendChild(creer("span", "detail-text", ligne.texte));
    detail.appendChild(row);
  });

  (fiche.fix || []).forEach((fix) => {
    detail.appendChild(construireCorrectif(fix, fiche.apres));
  });

  if (fiche.note) {
    const row = creer("div", "detail-row");
    row.setAttribute("data-kind", "note");
    row.appendChild(creer("span", "detail-tag", "Bon à savoir"));
    row.appendChild(creer("span", "detail-text", fiche.note));
    detail.appendChild(row);
  }

  return detail;
}

function construireObservation(obs) {
  const niveau = obs.niveau || "INFO";
  const libelle = obs.header || obs.critere || "Observation";

  const bloc = creer("div", "obs");
  bloc.setAttribute("data-niveau", niveau);

  const tete = creer("div", "obs-head");
  tete.appendChild(construirePastille(niveau));
  tete.appendChild(creer("span", "obs-label", libelle));
  bloc.appendChild(tete);

  bloc.appendChild(creer("p", "obs-message", obs.message || ""));

  if (obs.present && obs.valeur) {
    const valeur = obs.valeur.length > 220 ? obs.valeur.slice(0, 220) + "…" : obs.valeur;
    bloc.appendChild(creer("code", "obs-value", valeur));
  }

  // Explication, risque et correctif ne sont utiles que la ou il y a
  // quelque chose a corriger : un point conforme reste compact.
  const fiche = FICHES[libelle];
  if (fiche && niveau !== "OK") {
    bloc.appendChild(construireDetail(fiche));
  }

  return bloc;
}

/* ═══════════════════════════════════════════════════════════════
   8. Rendu : cartes repliables
   ═══════════════════════════════════════════════════════════════ */

function compterNiveaux(module) {
  const compte = { CRITIQUE: 0, AVERTISSEMENT: 0, INFO: 0, OK: 0 };
  (module.observations || []).forEach((obs) => {
    const niveau = obs.niveau || "INFO";
    if (niveau in compte) compte[niveau] += 1;
  });
  return compte;
}

function basculerCarte(carte, panneau, bouton, ouvrir) {
  carte.classList.toggle("is-open", ouvrir);
  bouton.setAttribute("aria-expanded", String(ouvrir));
  // inert retire le contenu replie du parcours clavier : sans lui, le
  // focus irait se poser sur des boutons invisibles.
  if (ouvrir) panneau.removeAttribute("inert");
  else panneau.setAttribute("inert", "");
}

function construireCarte(module, index) {
  const severite = severiteModule(module);

  const carte = creer("article", "card is-entering");
  carte.setAttribute("data-severity", severite);
  carte.style.setProperty("--i", String(index));

  const idPanneau = "panel-" + index;
  const idTete = "head-" + index;

  // Un bouton dans un titre : la carte reste une entree du plan du
  // document pour un lecteur d'ecran, et un controle pour le clavier.
  const titre = creer("h3", "card-head-wrap");
  const bouton = creer("button", "card-head");
  bouton.type = "button";
  bouton.id = idTete;
  bouton.setAttribute("aria-controls", idPanneau);

  bouton.appendChild(creer("span", "card-title", NOMS_MODULES[module.module] || module.module));

  const compte = compterNiveaux(module);
  const compteurs = creer("span", "card-counts");
  ["CRITIQUE", "AVERTISSEMENT", "INFO", "OK"].forEach((niveau) => {
    if (!compte[niveau]) return;
    const badge = creer("span", "mini-badge");
    badge.setAttribute("data-niveau", niveau);
    badge.textContent = GLYPHES[niveau] + " " + compte[niveau];
    // Le raccourci visuel est double d'un libelle pour la synthese vocale.
    badge.setAttribute("aria-label", compte[niveau] + " " + LIBELLES[niveau].toLowerCase());
    compteurs.appendChild(badge);
  });
  bouton.appendChild(compteurs);

  const chevron = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  chevron.setAttribute("class", "chevron");
  chevron.setAttribute("viewBox", "0 0 24 24");
  chevron.setAttribute("aria-hidden", "true");
  chevron.setAttribute("focusable", "false");
  chevron.innerHTML = '<path d="M6 9.5l6 6 6-6"/>';
  bouton.appendChild(chevron);

  titre.appendChild(bouton);
  carte.appendChild(titre);

  const panneau = creer("div", "card-panel");
  panneau.id = idPanneau;
  panneau.setAttribute("role", "region");
  panneau.setAttribute("aria-labelledby", idTete);

  const interieur = creer("div", "card-panel-inner");
  const corps = creer("div", "card-body");

  if (module.statut === "erreur") {
    corps.appendChild(creer("p", "module-error", "Module non exécuté : " + (module.message || "erreur inconnue")));
  } else {
    // Le plus grave d'abord : on voit ce qui compte sans faire defiler.
    const observations = (module.observations || [])
      .slice()
      .sort((a, b) => RANG[a.niveau || "INFO"] - RANG[b.niveau || "INFO"]);
    observations.forEach((obs) => corps.appendChild(construireObservation(obs)));
  }

  interieur.appendChild(corps);
  panneau.appendChild(interieur);
  carte.appendChild(panneau);

  // Les cartes qui portent un probleme critique s'ouvrent d'office.
  const ouvertParDefaut = severite === "CRITIQUE";
  basculerCarte(carte, panneau, bouton, ouvertParDefaut);

  bouton.addEventListener("click", () => {
    basculerCarte(carte, panneau, bouton, !carte.classList.contains("is-open"));
  });

  return carte;
}

/* ═══════════════════════════════════════════════════════════════
   9. Rendu du rapport complet
   ═══════════════════════════════════════════════════════════════ */

function afficherResultats(data) {
  dernierRapport = data;

  $("result-url").textContent = nomAffiche(data.url);
  $("result-note").textContent = data.score.note || "non attribuée";
  $("result-points-text").textContent = data.score.points;
  $("result-duree").textContent = data.duree;

  const moment = new Date(data.date_scan);
  $("result-date").dateTime = data.date_scan;
  $("result-date").textContent =
    moment.toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" }) +
    " à " + moment.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });

  const d = data.score.decompte || {};
  const comptes = {
    "tally-crit": ["CRITIQUE", d.CRITIQUE || 0],
    "tally-warn": ["AVERTISSEMENT", d.AVERTISSEMENT || 0],
    "tally-info": ["INFO", d.INFO || 0],
    "tally-ok": ["OK", d.OK || 0],
  };
  Object.entries(comptes).forEach(([id, [niveau, valeur]]) => {
    $(id).textContent = String(valeur);
    const item = document.querySelector('.tally-item[data-niveau="' + niveau + '"]');
    item.classList.toggle("is-flagged", valeur > 0);
  });

  // Quand un module n'a pas abouti, reporter.py l'exclut du calcul :
  // la note ne couvre alors qu'une partie des contrôles, et cela doit
  // se lire a cote du score, pas seulement dans la carte du module.
  const avis = $("avis-partiel");
  if (avis) {
    const complet = data.score.complet !== undefined
      ? data.score.complet
      : (data.modules || []).every((m) => m.statut !== "erreur");

    avis.hidden = complet;
    if (!complet) {
      const manquants = (data.score.modules_non_executes ||
        (data.modules || []).filter((m) => m.statut === "erreur").map((m) => m.module))
        .map((nom) => NOMS_MODULES[nom] || nom);

      $("avis-partiel-texte").textContent =
        "Audit partiel : " + manquants.join(" et ") + " n'a pas répondu dans le délai "
        + "imparti. La note ne porte que sur les contrôles qui ont abouti — elle ne vaut "
        + "pas quitus. Relancez l'audit avant de conclure.";
    }
  }

  modulesContainer.innerHTML = "";
  (data.modules || []).forEach((module, i) => {
    modulesContainer.appendChild(construireCarte(module, i));
  });

  afficher("results");

  // Le tampon et la jauge s'animent apres l'affichage de la section,
  // sinon la transition demarre sur un element encore masque.
  requestAnimationFrame(() => poserTampon(data.score));

  afficherHistorique(data.url);
}

/* ═══════════════════════════════════════════════════════════════
   9 bis. Évolution du score (historique, C01)
   ═══════════════════════════════════════════════════════════════ */

const SVG_NS = "http://www.w3.org/2000/svg";

function elementSvg(nom, attributs) {
  const el = document.createElementNS(SVG_NS, nom);
  Object.entries(attributs || {}).forEach(([cle, valeur]) => el.setAttribute(cle, valeur));
  return el;
}

function dateCourte(iso) {
  const moment = new Date(iso);
  return moment.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric" });
}

function dateLongue(iso) {
  const moment = new Date(iso);
  return dateCourte(iso) + " à " +
    moment.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

/**
 * Courbe SVG simple : dates en abscisse (à l'échelle du temps), points
 * sur 100 en ordonnée. Chaque point porte sa valeur et sa date dans un
 * <title>, affiché au survol.
 */
function construireCourbe(scans) {
  const L = 420, H = 200;
  const marge = { gauche: 36, droite: 12, haut: 14, bas: 34 };
  const largeur = L - marge.gauche - marge.droite;
  const hauteur = H - marge.haut - marge.bas;

  const temps = scans.map((s) => new Date(s.date_scan).getTime());
  const tMin = Math.min(...temps);
  const tMax = Math.max(...temps);
  const x = (i) => marge.gauche + (tMax > tMin
    ? (temps[i] - tMin) / (tMax - tMin) * largeur
    : i / (scans.length - 1) * largeur);
  const y = (points) => marge.haut + (1 - Math.max(0, Math.min(100, points)) / 100) * hauteur;

  const svg = elementSvg("svg", {
    class: "courbe", viewBox: "0 0 " + L + " " + H, role: "img",
    "aria-label": "Évolution du score sur " + scans.length + " scans",
  });

  // Graduations horizontales : 0, 50 et 100 points.
  [0, 50, 100].forEach((valeur) => {
    svg.appendChild(elementSvg("line", {
      class: "courbe-grille", x1: marge.gauche, x2: L - marge.droite, y1: y(valeur), y2: y(valeur),
    }));
    const etiquette = elementSvg("text", {
      class: "courbe-etiquette", x: marge.gauche - 8, y: y(valeur) + 4, "text-anchor": "end",
    });
    etiquette.textContent = String(valeur);
    svg.appendChild(etiquette);
  });

  // Dates du premier et du dernier scan sous l'axe.
  [[0, "start"], [scans.length - 1, "end"]].forEach(([i, ancre]) => {
    const etiquette = elementSvg("text", {
      class: "courbe-etiquette", x: x(i), y: H - 10, "text-anchor": ancre,
    });
    etiquette.textContent = dateCourte(scans[i].date_scan);
    svg.appendChild(etiquette);
  });

  svg.appendChild(elementSvg("polyline", {
    class: "courbe-ligne",
    points: scans.map((s, i) => x(i).toFixed(1) + "," + y(s.points).toFixed(1)).join(" "),
  }));

  scans.forEach((s, i) => {
    const point = elementSvg("circle", { class: "courbe-point", cx: x(i), cy: y(s.points), r: 4.5 });
    const titre = elementSvg("title");
    titre.textContent = dateLongue(s.date_scan) + " : " + s.points + "/100"
      + (s.note ? " (" + s.note + ")" : " (note non attribuée)");
    point.appendChild(titre);
    svg.appendChild(point);
  });

  return svg;
}

async function afficherHistorique(url) {
  const section = $("historique");
  const contenu = $("historique-contenu");
  contenu.innerHTML = "";
  section.hidden = true;

  try {
    const reponse = await fetch("/api/history?url=" + encodeURIComponent(url));
    if (!reponse.ok) return;
    const data = await reponse.json();
    const scans = (data.scans || []).filter((s) => typeof s.points === "number");

    if (scans.length >= 2) {
      contenu.appendChild(construireCourbe(scans));
    } else {
      contenu.appendChild(creer("p", "historique-vide", "Premier scan enregistré pour cet hôte"));
    }
    section.hidden = false;
  } catch (err) {
    // L'historique est un complément : son absence ne gêne pas le rapport.
  }
}

/* ═══════════════════════════════════════════════════════════════
   10. Appel au scanner
   ═══════════════════════════════════════════════════════════════ */

async function lancerScan(url) {
  reinitialiserEtapes();
  loadingUrl.textContent = url;
  loadingStatus.textContent = "Audit en cours.";
  afficher("loading");

  const animation = animerEtapes();
  const requete = fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url, autorisation: caseAutorisation.checked }),
  });

  try {
    const [, reponse] = await Promise.all([animation, requete]);
    const data = await reponse.json();

    if (!reponse.ok) {
      throw new Error(data.erreur || "Une erreur est survenue pendant l'audit.");
    }
    // Cible injoignable : ni points ni note, seulement le motif (E15).
    if (data.statut === "impossible") {
      throw new Error("Scan impossible : " + data.motif
                      + ". Aucun point ni aucune note ne sont attribués.");
    }

    terminerCompilation();
    loadingStatus.textContent = "Audit terminé.";
    await pause(320);
    afficherResultats(data);
  } catch (err) {
    errorText.textContent = err.message || "Impossible de joindre le serveur. Réessayez.";
    afficher("error");
  } finally {
    majBoutonScan();
  }
}

/* ═══════════════════════════════════════════════════════════════
   11. Telechargement des rapports
   ═══════════════════════════════════════════════════════════════ */

$("download-txt-btn").addEventListener("click", () => {
  if (!dernierRapport) return;
  telecharger(dernierRapport.rapport_texte,
              "webaudit-" + baseNomFichier(dernierRapport.url) + ".txt",
              "text/plain;charset=utf-8");
});

$("download-json-btn").addEventListener("click", () => {
  if (!dernierRapport) return;
  telecharger(JSON.stringify(dernierRapport, null, 2),
              "webaudit-" + baseNomFichier(dernierRapport.url) + ".json",
              "application/json");
});

// Le PDF est mis en page par le serveur (pdf_reporter.py) a partir du
// rapport deja affiche : le document correspond donc exactement a ce
// que l'utilisateur a sous les yeux, sans relancer de scan.
const pdfBtn = $("download-pdf-btn");
const pdfLabel = pdfBtn.querySelector(".btn-ghost-label");

pdfBtn.addEventListener("click", async () => {
  if (!dernierRapport || pdfBtn.disabled) return;

  const texteInitial = pdfLabel.textContent;
  pdfBtn.disabled = true;
  pdfLabel.textContent = "Préparation…";

  try {
    const reponse = await fetch("/api/rapport-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(dernierRapport),
    });

    if (!reponse.ok) {
      const erreur = await reponse.json().catch(() => ({}));
      throw new Error(erreur.erreur || "Le rapport PDF n'a pas pu être généré.");
    }

    telecharger(await reponse.blob(),
                "webaudit-" + baseNomFichier(dernierRapport.url) + ".pdf");
    pdfLabel.textContent = texteInitial;
  } catch (err) {
    pdfLabel.textContent = "Échec — réessayer";
    setTimeout(() => { pdfLabel.textContent = texteInitial; }, 2400);
  } finally {
    pdfBtn.disabled = false;
  }
});

/* ═══════════════════════════════════════════════════════════════
   12. Evenements de navigation
   ═══════════════════════════════════════════════════════════════ */

form.addEventListener("submit", (e) => {
  e.preventDefault();
  champTouche = true;
  if (!caseAutorisation.checked) return;

  const message = validerUrl(urlInput.value);
  afficherErreurChamp(message);
  if (message) {
    urlInput.focus();
    return;
  }

  scanBtn.disabled = true;
  lancerScan(urlInput.value.trim());
});

$("error-retry").addEventListener("click", () => {
  afficher("hero");
  urlInput.focus();
});

$("new-scan-btn").addEventListener("click", () => {
  afficher("hero");
  urlInput.value = "";
  afficherErreurChamp(null);
  champTouche = false;
  urlInput.focus();
});
