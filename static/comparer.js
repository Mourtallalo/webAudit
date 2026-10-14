/**
 * comparer.js
 * ===========
 * Page de comparaison multi-sites.
 *
 * Les scans sont enchaines un par un, jamais en parallele : c'est plus
 * long, mais cela evite d'ouvrir une rafale de connexions vers des
 * serveurs que l'on ne possede pas. Chaque adresse passe par la meme
 * route /api/scan que la page d'audit, donc par le meme controle
 * d'adresse (refus des hotes locaux et prives) et le meme delai maximum.
 *
 * Auteur : Mourtalla LO
 * Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
 */

"use strict";

const MAX_URLS = window.MAX_URLS || 30;

/* ═══════════════════════════════════════════════════════════════
   1. References DOM
   ═══════════════════════════════════════════════════════════════ */

const ecrans = {
  saisie: $("saisie-section"),
  campagne: $("campagne-section"),
  classement: $("classement-section"),
};

const listeForm = $("liste-form");
const urlsInput = $("urls-input");
const compteurUrls = $("compteur-urls");
const listeError = $("liste-error");
const listeHint = $("liste-hint");
const lancerBtn = $("lancer-btn");
const caseAutorisation = $("autorisation");

// E26 : le bouton reste désactivé tant que la case n'est pas cochée.
function majBoutonLancer() {
  lancerBtn.disabled = !caseAutorisation.checked;
}
caseAutorisation.addEventListener("change", majBoutonLancer);
// Le navigateur peut restaurer l'état de la case au rechargement.
majBoutonLancer();

const faitEl = $("fait");
const totalEl = $("total");
const campagneBar = $("campagne-bar");
const campagneProgress = $("campagne-progress");
const cibleCourante = $("cible-courante");
const journal = $("journal");
const arreterBtn = $("arreter-btn");
const campagneStatus = $("campagne-status");

let resultats = [];
let echecs = [];
let campagneInterrompue = false;
let requeteEnCours = null;

/* ═══════════════════════════════════════════════════════════════
   2. Lecture de la liste d'adresses
   ═══════════════════════════════════════════════════════════════ */

/**
 * Decoupe le contenu de la zone de texte en adresses exploitables.
 * Les lignes vides sont ignorees et les doublons retires, en
 * comparant sur le nom d'hote pour que "exemple.com" et
 * "https://exemple.com/" ne soient pas scannes deux fois.
 */
function lireListe() {
  const vues = new Set();
  const adresses = [];

  urlsInput.value.split("\n").forEach((ligne) => {
    const brut = ligne.trim();
    if (!brut) return;

    let cle = brut.toLowerCase();
    try {
      const complete = /^https?:\/\//i.test(brut) ? brut : "https://" + brut;
      cle = new URL(complete).hostname.toLowerCase();
    } catch (e) { /* adresse illisible : la validation la signalera */ }

    if (vues.has(cle)) return;
    vues.add(cle);
    adresses.push(brut);
  });

  return adresses;
}

function majCompteur() {
  const nombre = lireListe().length;
  compteurUrls.textContent = nombre + " / " + MAX_URLS;
  compteurUrls.classList.toggle("is-over", nombre > MAX_URLS);
}

function afficherErreurListe(message) {
  if (message) {
    listeError.textContent = message;
    listeError.hidden = false;
    urlsInput.setAttribute("aria-invalid", "true");
    listeHint.hidden = true;
  } else {
    listeError.hidden = true;
    listeError.textContent = "";
    urlsInput.removeAttribute("aria-invalid");
    listeHint.hidden = false;
  }
}

urlsInput.addEventListener("input", () => {
  majCompteur();
  if (!listeError.hidden) afficherErreurListe(null);
});

/**
 * Verifie la liste entiere avant de lancer quoi que ce soit : mieux
 * vaut signaler une faute de frappe maintenant qu'au bout de douze
 * scans. Les regles sont celles du serveur (commun.js : validerUrl).
 */
function validerListe(adresses) {
  if (adresses.length === 0) {
    return "Saisissez au moins une adresse.";
  }
  if (adresses.length > MAX_URLS) {
    return "La campagne est limitée à " + MAX_URLS + " adresses — vous en avez saisi "
         + adresses.length + ".";
  }

  const fautives = [];
  adresses.forEach((adresse, i) => {
    const probleme = validerUrl(adresse);
    if (probleme) fautives.push("ligne " + (i + 1) + " (" + adresse + ") : " + probleme);
  });

  if (fautives.length === 1) return fautives[0];
  if (fautives.length > 1) {
    return fautives.length + " adresses sont invalides — " + fautives[0];
  }
  return null;
}

/* ═══════════════════════════════════════════════════════════════
   3. Navigation entre ecrans
   ═══════════════════════════════════════════════════════════════ */

function afficherEcran(nom) {
  Object.entries(ecrans).forEach(([cle, section]) => {
    section.hidden = cle !== nom;
  });
}

/* ═══════════════════════════════════════════════════════════════
   4. Deroulement de la campagne
   ═══════════════════════════════════════════════════════════════ */

function poserProgressionCampagne(fait, total) {
  const pourcent = total ? Math.round((fait / total) * 100) : 0;
  campagneBar.style.width = pourcent + "%";
  campagneProgress.setAttribute("aria-valuenow", String(pourcent));
  animerCompteur(faitEl, fait, 320);
}

/** Ajoute une ligne au journal de la campagne, au fil des scans. */
function journaliser(adresse, note, severite, message) {
  const ligne = creer("li", "journal-item");
  ligne.setAttribute("data-niveau", severite);

  const badge = creer("span", "journal-note");
  badge.textContent = note;
  ligne.appendChild(badge);

  ligne.appendChild(creer("span", "journal-url", nomAffiche(adresse)));
  if (message) ligne.appendChild(creer("span", "journal-message", message));

  journal.prepend(ligne);
}

async function scannerUne(adresse) {
  requeteEnCours = new AbortController();
  try {
    const reponse = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: adresse, autorisation: caseAutorisation.checked }),
      signal: requeteEnCours.signal,
    });
    const data = await reponse.json();
    if (!reponse.ok) throw new Error(data.erreur || "Audit impossible.");
    // Cible injoignable : ni points ni note, le site rejoint les échecs (E15).
    if (data.statut === "impossible") throw new Error("Scan impossible : " + data.motif);
    return data;
  } finally {
    requeteEnCours = null;
  }
}

async function lancerCampagne(adresses) {
  resultats = [];
  echecs = [];
  campagneInterrompue = false;
  journal.innerHTML = "";

  totalEl.textContent = String(adresses.length);
  faitEl.textContent = "0";
  poserProgressionCampagne(0, adresses.length);
  afficherEcran("campagne");

  for (let i = 0; i < adresses.length; i++) {
    if (campagneInterrompue) break;

    const adresse = adresses[i];
    cibleCourante.textContent = nomAffiche(adresse);
    campagneStatus.textContent = "Audit " + (i + 1) + " sur " + adresses.length
                               + " : " + nomAffiche(adresse);

    try {
      const data = await scannerUne(adresse);
      resultats.push(data);
      journaliser(data.url, noteAffichee(data.score.note),
                  severiteDeLaNote(data.score.note),
                  data.score.points + "/100");
    } catch (err) {
      if (err.name === "AbortError") break;
      echecs.push({ url: adresse, message: err.message || "Audit impossible." });
      journaliser(adresse, "—", "CRITIQUE", err.message || "Audit impossible.");
    }

    poserProgressionCampagne(i + 1, adresses.length);

    // Courte respiration entre deux cibles : la campagne reste lisible
    // a l'ecran, et l'enchainement ne ressemble pas a une rafale.
    if (i < adresses.length - 1 && !campagneInterrompue) await pause(220);
  }

  if (resultats.length === 0 && echecs.length === 0) {
    afficherEcran("saisie");
    return;
  }

  afficherClassement();
}

arreterBtn.addEventListener("click", () => {
  campagneInterrompue = true;
  campagneStatus.textContent = "Campagne interrompue.";
  if (requeteEnCours) requeteEnCours.abort();
});

/* ═══════════════════════════════════════════════════════════════
   5. Lecture des resultats
   Les champs sont cherches dans "details" quand il est present, avec
   repli sur les observations : l'affichage ne doit pas dependre d'un
   seul chemin de donnees.
   ═══════════════════════════════════════════════════════════════ */

function moduleNomme(data, nom) {
  return (data.modules || []).find((m) => m.module === nom) || null;
}

function observationNommee(module, critere) {
  if (!module) return null;
  return (module.observations || []).find(
    (o) => (o.critere || o.header) === critere) || null;
}

function httpsActif(data) {
  const module = moduleNomme(data, "HTTPS / TLS");
  if (module && module.details && module.details.certificat) {
    return Boolean(module.details.certificat.https_actif);
  }
  const obs = observationNommee(module, "Disponibilité HTTPS");
  return Boolean(obs && obs.niveau === "OK");
}

function cmsDetecte(data) {
  const module = moduleNomme(data, "Detection CMS");
  if (module && module.details && module.details.cms) {
    const version = module.details.version;
    return version ? module.details.cms + " " + version : module.details.cms;
  }
  return null;
}

function ligneResultat(data) {
  const decompte = data.score.decompte || {};

  // reporter.py exclut du calcul les modules qui n'ont pas abouti et
  // le signale par "complet". La note ne porte alors que sur une partie
  // des controles : dans un classement, cela doit se voir.
  // Le repli sur l'inspection des modules garde la page compatible avec
  // un resultat produit par une version anterieure du scanner.
  const modulesKo = (data.modules || []).filter((m) => m.statut === "erreur");
  const complet = data.score.complet !== undefined
    ? data.score.complet
    : modulesKo.length === 0;

  return {
    url: data.url,
    site: nomAffiche(data.url),
    points: data.score.points,
    note: data.score.note,
    critiques: decompte.CRITIQUE || 0,
    https: httpsActif(data),
    cms: cmsDetecte(data),
    partiel: !complet,
    modulesKo: (data.score.modules_non_executes || modulesKo.map((m) => m.module))
      .map((nom) => NOMS_MODULES[nom] || nom),
  };
}

/* ═══════════════════════════════════════════════════════════════
   6. Rendu du classement
   ═══════════════════════════════════════════════════════════════ */

const MEDAILLES = ["1", "2", "3"];

function construirePodium(lignes) {
  const podium = $("podium");
  podium.innerHTML = "";

  // Le podium distingue les meilleurs : on ne peut pas y faire figurer
  // un site dont une partie des controles n'a pas abouti, puisque sa
  // note ne repose pas sur la meme base que celle des autres. Il reste
  // dans le graphique et le tableau, marque comme partiel.
  lignes.filter((l) => !l.partiel).slice(0, 3).forEach((ligne, i) => {
    const severite = severiteDeLaNote(ligne.note);
    const item = creer("li", "podium-item");
    item.setAttribute("data-rang", String(i + 1));
    item.setAttribute("data-niveau", severite);

    item.appendChild(creer("span", "podium-rang", MEDAILLES[i]));

    const corps = creer("div", "podium-corps");
    corps.appendChild(creer("p", "podium-site", ligne.site));
    corps.appendChild(creer("p", "podium-score", ligne.points + "/100"));
    item.appendChild(corps);

    const note = creer("span", "podium-note", noteAffichee(ligne.note));
    item.appendChild(note);

    podium.appendChild(item);
  });
}

/**
 * Graphique a barres horizontales, trie du meilleur au moins bon.
 *
 * La longueur porte la valeur ; la couleur ne porte que la classe de
 * note (conforme / a surveiller / critique), information que la
 * longueur seule ne donne pas. Chaque barre affiche en clair sa valeur
 * et sa lettre, de sorte que rien ne repose sur la teinte.
 */
function construireBarres(lignes) {
  const barres = $("barres");
  barres.innerHTML = "";

  lignes.forEach((ligne, i) => {
    const severite = severiteDeLaNote(ligne.note);

    const rang = creer("div", "barre-ligne");
    rang.setAttribute("data-niveau", severite);
    rang.setAttribute("title", ligne.site + " — " + ligne.points + "/100, note "
                             + (ligne.note || "non attribuée")
                             + ", " + ligne.critiques + " critique(s)"
                             + (ligne.partiel ? " — scan partiel : " + ligne.modulesKo.join(", ") : ""));
    if (ligne.partiel) rang.classList.add("is-partiel");

    const nom = creer("span", "barre-site", ligne.site);
    if (ligne.partiel) nom.appendChild(creer("span", "marque-partiel", "partiel"));
    rang.appendChild(nom);

    const piste = creer("div", "barre-piste");
    const remplissage = creer("div", "barre-remplissage");
    remplissage.style.setProperty("--i", String(i));
    // La largeur est posee au cycle suivant pour que la transition joue.
    requestAnimationFrame(() => {
      remplissage.style.width = Math.max(ligne.points, 1.5) + "%";
    });
    piste.appendChild(remplissage);
    rang.appendChild(piste);

    const valeur = creer("span", "barre-valeur");
    valeur.appendChild(creer("b", null, String(ligne.points)));
    valeur.appendChild(creer("span", "barre-note", noteAffichee(ligne.note)));
    rang.appendChild(valeur);

    barres.appendChild(rang);
  });
}

function construireTableau(lignes) {
  const corps = $("tableau-corps");
  corps.innerHTML = "";

  lignes.forEach((ligne, i) => {
    const severite = severiteDeLaNote(ligne.note);
    const tr = document.createElement("tr");
    tr.setAttribute("data-niveau", severite);

    const rang = document.createElement("th");
    rang.setAttribute("scope", "row");
    rang.className = "col-rang";
    rang.textContent = String(i + 1);
    tr.appendChild(rang);

    const site = creer("td", "col-site");
    const lien = creer("a", "lien-site", ligne.site);
    lien.href = ligne.url;
    lien.target = "_blank";
    lien.rel = "noopener noreferrer";
    site.appendChild(lien);
    tr.appendChild(site);

    tr.appendChild(creer("td", "col-num", String(ligne.points)));

    const note = creer("td");
    const badge = creer("span", "note-badge", noteAffichee(ligne.note));
    badge.setAttribute("data-niveau", severite);
    note.appendChild(badge);
    if (ligne.partiel) {
      const marque = creer("span", "marque-partiel", "partiel");
      marque.title = "Modules sans réponse dans le délai : " + ligne.modulesKo.join(", ")
                   + ". Ces contrôles ne sont pas comptés, donc le score est flatteur "
                   + "et aucune note n'est attribuée.";
      note.appendChild(marque);
    }
    tr.appendChild(note);

    const critiques = creer("td", "col-num");
    if (ligne.critiques > 0) {
      const marque = creer("span", "compte-critique", String(ligne.critiques));
      critiques.appendChild(marque);
    } else {
      critiques.textContent = "0";
    }
    tr.appendChild(critiques);

    // Oui/non en toutes lettres, double d'un glyphe : la colonne reste
    // lisible sans distinguer les couleurs.
    const https = creer("td");
    const marqueHttps = creer("span", "oui-non", ligne.https ? "✓ oui" : "✕ non");
    marqueHttps.setAttribute("data-valeur", ligne.https ? "oui" : "non");
    https.appendChild(marqueHttps);
    tr.appendChild(https);

    tr.appendChild(creer("td", "col-cms", ligne.cms || "aucun détecté"));

    corps.appendChild(tr);
  });
}

function construireEchecs() {
  const bloc = $("echecs");
  const liste = $("echecs-liste");
  liste.innerHTML = "";

  if (echecs.length === 0) {
    bloc.hidden = true;
    return;
  }

  echecs.forEach((echec) => {
    const item = creer("li", "echec-item");
    item.appendChild(creer("span", "echec-url", nomAffiche(echec.url)));
    item.appendChild(creer("span", "echec-message", echec.message));
    liste.appendChild(item);
  });
  bloc.hidden = false;
}

function afficherClassement() {
  const lignes = resultats.map(ligneResultat).sort((a, b) => b.points - a.points);

  $("nb-sites").textContent = String(lignes.length);

  const moyenne = lignes.length
    ? Math.round(lignes.reduce((somme, l) => somme + l.points, 0) / lignes.length)
    : 0;
  const totalCritiques = lignes.reduce((somme, l) => somme + l.critiques, 0);
  const sansHttps = lignes.filter((l) => !l.https).length;

  const partiels = lignes.filter((l) => l.partiel).length;

  const morceaux = ["score moyen " + moyenne + "/100", totalCritiques + " problèmes critiques au total"];
  if (sansHttps > 0) {
    morceaux.push(sansHttps + (sansHttps > 1 ? " sites sans HTTPS" : " site sans HTTPS"));
  }
  if (partiels > 0) {
    morceaux.push(partiels + (partiels > 1 ? " scans partiels" : " scan partiel"));
  }
  if (echecs.length > 0) {
    morceaux.push(echecs.length + (echecs.length > 1 ? " adresses non auditées" : " adresse non auditée"));
  }
  $("classement-resume").textContent = morceaux.join(" · ");

  // Rappel explicite quand des mesures manquent : une note basse due a
  // un depassement de delai ne dit rien de la securite du site.
  const avis = $("avis-partiel");
  if (avis) {
    avis.hidden = partiels === 0;
    if (partiels > 0) {
      // Attention au sens : les contrôles manquants ne sont pas comptés,
      // donc le score restant est mécaniquement flatteur. C'est l'inverse
      // du piège habituel, et c'est pour cela qu'aucune note n'est posée.
      $("avis-partiel-texte").textContent =
        partiels > 1
          ? partiels + " sites n'ont pas répondu à tous les contrôles dans le délai de 10 secondes. "
            + "Aucune note ne leur est attribuée : leur score ne porte que sur les contrôles "
            + "aboutis, il est donc flatteur et n'est pas comparable aux autres. Ils sont exclus "
            + "du podium. Relancez leur audit avant de conclure."
          : "Un site n'a pas répondu à tous les contrôles dans le délai de 10 secondes. "
            + "Aucune note ne lui est attribuée : son score ne porte que sur les contrôles "
            + "aboutis, il est donc flatteur et n'est pas comparable aux autres. Il est exclu "
            + "du podium. Relancez son audit avant de conclure.";
    }
  }

  construirePodium(lignes);
  construireBarres(lignes);
  construireTableau(lignes);
  construireEchecs();

  afficherEcran("classement");
  window.scrollTo({ top: 0, behavior: mouvementReduit() ? "auto" : "smooth" });
}

/* ═══════════════════════════════════════════════════════════════
   7. Export CSV
   ═══════════════════════════════════════════════════════════════ */

/** Echappe une valeur selon la convention CSV (guillemets doubles). */
function champCsv(valeur) {
  const texte = String(valeur === null || valeur === undefined ? "" : valeur);
  return '"' + texte.replace(/"/g, '""') + '"';
}

function construireCsv() {
  const lignes = resultats.map(ligneResultat).sort((a, b) => b.points - a.points);

  const entetes = ["Site", "Score", "Note", "Problemes critiques", "HTTPS",
                   "CMS detecte", "Scan complet"];
  const corps = lignes.map((l) => [
    l.site,
    l.points,
    l.note || "non attribuee",
    l.critiques,
    l.https ? "oui" : "non",
    l.cms || "aucun",
    l.partiel ? "non (" + l.modulesKo.join(", ") + ")" : "oui",
  ]);

  // Separateur point-virgule : c'est celui qu'attend Excel en
  // configuration francaise. Le BOM en tete lui fait lire l'UTF-8,
  // sans quoi les accents ressortent abimes.
  const texte = [entetes, ...corps]
    .map((ligne) => ligne.map(champCsv).join(";"))
    .join("\r\n");

  return "﻿" + texte;
}

$("export-csv-btn").addEventListener("click", () => {
  if (resultats.length === 0) return;
  const horodatage = new Date().toISOString().slice(0, 10);
  telecharger(construireCsv(), "webaudit-comparaison-" + horodatage + ".csv",
              "text/csv;charset=utf-8");
});

/* ═══════════════════════════════════════════════════════════════
   8. Evenements
   ═══════════════════════════════════════════════════════════════ */

listeForm.addEventListener("submit", (e) => {
  e.preventDefault();
  if (!caseAutorisation.checked) return;

  const adresses = lireListe();
  const probleme = validerListe(adresses);
  afficherErreurListe(probleme);

  if (probleme) {
    urlsInput.focus();
    return;
  }

  lancerBtn.disabled = true;
  lancerCampagne(adresses).finally(majBoutonLancer);
});

$("nouvelle-campagne-btn").addEventListener("click", () => {
  afficherEcran("saisie");
  urlsInput.focus();
});

majCompteur();
