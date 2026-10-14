/**
 * commun.js
 * =========
 * Briques partagees par la page d'audit et la page de comparaison :
 * theme, validation d'URL, severites, telechargement, presse-papiers.
 *
 * Charge avant les scripts de page, qui s'appuient sur ces fonctions.
 *
 * Auteur : Mourtalla LO
 * Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
 */

"use strict";

/* ═══════════════════════════════════════════════════════════════
   1. Severites
   Les glyphes reprennent ceux du rapport texte (reporter.py).
   ═══════════════════════════════════════════════════════════════ */

const GLYPHES = {
  CRITIQUE: "!",
  AVERTISSEMENT: "~",
  INFO: "i",
  OK: "✓",
};

const LIBELLES = {
  CRITIQUE: "CRITIQUE",
  AVERTISSEMENT: "À SURVEILLER",
  INFO: "INFO",
  OK: "CONFORME",
};

// Du plus grave au moins grave : sert au tri et au choix de la
// severite representative d'un ensemble d'observations.
const RANG = { CRITIQUE: 0, AVERTISSEMENT: 1, INFO: 2, OK: 3 };

const NOMS_MODULES = {
  "En-tetes HTTP": "En-têtes HTTP de sécurité",
  "HTTPS / TLS": "HTTPS et certificat TLS",
  "Detection CMS": "Détection du CMS",
};

/* ═══════════════════════════════════════════════════════════════
   2. Raccourcis DOM
   ═══════════════════════════════════════════════════════════════ */

const $ = (id) => document.getElementById(id);

function creer(balise, classe, texte) {
  const el = document.createElement(balise);
  if (classe) el.className = classe;
  if (texte !== undefined) el.textContent = texte;
  return el;
}

/* ═══════════════════════════════════════════════════════════════
   3. Preferences de mouvement
   ═══════════════════════════════════════════════════════════════ */

const mediaMouvement = window.matchMedia("(prefers-reduced-motion: reduce)");
const mouvementReduit = () => mediaMouvement.matches;

const pause = (ms) => new Promise((r) => setTimeout(r, mouvementReduit() ? 0 : ms));

/**
 * Fait defiler un compteur de 0 vers sa valeur finale.
 * Saute l'animation si le systeme demande moins de mouvement.
 *
 * Le navigateur suspend requestAnimationFrame dans un onglet passe en
 * arriere-plan : l'animation se figerait alors sur une valeur
 * intermediaire et n'arriverait jamais a destination. Un minuteur de
 * securite, lui, continue de tourner et pose la valeur finale.
 */
function animerCompteur(el, cible, duree) {
  const valeur = Number(cible) || 0;

  if (mouvementReduit()) {
    el.textContent = String(valeur);
    return;
  }

  // Marque cette animation : si une autre demarre entre-temps sur le
  // meme element, l'ancienne cesse d'ecrire.
  const jeton = (el._jetonCompteur = (el._jetonCompteur || 0) + 1);
  const depart = performance.now();

  function etape(maintenant) {
    if (el._jetonCompteur !== jeton) return;
    const avance = Math.min((maintenant - depart) / duree, 1);
    // Sortie en douceur : rapide au debut, ralentit a l'arrivee.
    const adouci = 1 - Math.pow(1 - avance, 3);
    el.textContent = String(Math.round(valeur * adouci));
    if (avance < 1) requestAnimationFrame(etape);
  }
  requestAnimationFrame(etape);

  setTimeout(() => {
    if (el._jetonCompteur === jeton) el.textContent = String(valeur);
  }, duree + 120);
}

/* ═══════════════════════════════════════════════════════════════
   4. Theme clair / sombre
   ═══════════════════════════════════════════════════════════════ */

function initialiserTheme() {
  const bouton = $("theme-toggle");
  const etiquette = $("theme-toggle-text");
  if (!bouton) return;

  function themeActuel() {
    const pose = document.documentElement.getAttribute("data-theme");
    if (pose === "light" || pose === "dark") return pose;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function majBouton() {
    const sombre = themeActuel() === "dark";
    // Le bouton annonce la destination, pas l'etat courant.
    etiquette.textContent = sombre ? "Clair" : "Sombre";
    bouton.setAttribute("aria-label", sombre ? "Activer le thème clair" : "Activer le thème sombre");
  }

  bouton.addEventListener("click", () => {
    const cible = themeActuel() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", cible);
    try {
      localStorage.setItem("webaudit-theme", cible);
    } catch (e) { /* navigation privee : le choix ne survivra pas au rechargement */ }
    majBouton();
  });

  majBouton();
}

/* ═══════════════════════════════════════════════════════════════
   5. Validation d'URL
   Les regles refletent celles du serveur (app.py : url_valide),
   pour signaler l'erreur avant meme d'envoyer la requete.
   ═══════════════════════════════════════════════════════════════ */

function validerUrl(valeur) {
  const brut = String(valeur || "").trim();

  if (!brut) return "Saisissez l'adresse du site à auditer.";
  if (/\s/.test(brut)) return "L'adresse ne doit pas contenir d'espace.";

  const complete = /^https?:\/\//i.test(brut) ? brut : "https://" + brut;

  let hote;
  try {
    hote = new URL(complete).hostname.toLowerCase();
  } catch (e) {
    return "Cette adresse n'est pas lisible. Exemple attendu : exemple.com";
  }

  if (!hote) return "Il manque le nom de domaine. Exemple : exemple.com";

  const estLocal =
    ["localhost", "127.0.0.1", "0.0.0.0"].includes(hote) ||
    hote.startsWith("192.168.") ||
    hote.startsWith("10.");
  if (estLocal) {
    return "Les adresses locales ou privées ne peuvent pas être auditées depuis cette interface.";
  }

  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(hote)) {
    return "Le nom de domaine semble incomplet. Exemple : exemple.com";
  }

  return null;
}

/** Retire le schema pour l'affichage : "https://exemple.com" -> "exemple.com". */
const nomAffiche = (url) => String(url || "").replace(/^https?:\/\//, "").replace(/\/$/, "");

/* ═══════════════════════════════════════════════════════════════
   6. Severite d'un ensemble d'observations
   ═══════════════════════════════════════════════════════════════ */

// A+/A/B : conforme · C/D : a surveiller · E/F : critique.
// reporter.py ne pose aucune lettre quand l'audit est partiel : le
// resultat est alors neutre, ni bon ni mauvais, puisque la mesure est
// incomplete. Le teinter en rouge ou en vert serait un contresens.
const NOTE_ABSENTE = "—";

function severiteDeLaNote(note) {
  if (!note) return "NEUTRE";
  if (["A+", "A", "B"].includes(note)) return "OK";
  if (["C", "D"].includes(note)) return "AVERTISSEMENT";
  return "CRITIQUE";
}

/** La lettre a afficher, ou un tiret quand elle n'a pas ete attribuee. */
const noteAffichee = (note) => note || NOTE_ABSENTE;

function severiteModule(module) {
  if (module.statut === "erreur") return "CRITIQUE";
  return (module.observations || []).reduce((pire, obs) => {
    const niveau = obs.niveau || "INFO";
    return RANG[niveau] < RANG[pire] ? niveau : pire;
  }, "OK");
}

/* ═══════════════════════════════════════════════════════════════
   7. Telechargement et presse-papiers
   ═══════════════════════════════════════════════════════════════ */

function telecharger(contenu, nomFichier, typeMime) {
  const blob = contenu instanceof Blob ? contenu : new Blob([contenu], { type: typeMime });
  const url = URL.createObjectURL(blob);
  const lien = document.createElement("a");
  lien.href = url;
  lien.download = nomFichier;
  document.body.appendChild(lien);
  lien.click();
  document.body.removeChild(lien);
  URL.revokeObjectURL(url);
}

/** Transforme une adresse en base de nom de fichier sure. */
function baseNomFichier(url) {
  return nomAffiche(url).replace(/[^a-z0-9.-]/gi, "_").replace(/_+$/, "");
}

/**
 * Ecrit dans le presse-papiers en essayant deux voies successives.
 *
 * L'API moderne echoue dans plusieurs situations courantes — page
 * servie en http:// simple, document sans le focus, permission
 * refusee — et lever une erreur ne doit pas priver l'utilisateur du
 * correctif. On retombe alors sur la selection d'une zone de texte
 * masquee, qui reste acceptee partout.
 */
async function ecrireDansPressePapiers(texte) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(texte);
      return true;
    } catch (e) { /* on tente le repli ci-dessous */ }
  }

  try {
    const zone = document.createElement("textarea");
    zone.value = texte;
    zone.setAttribute("readonly", "");
    zone.style.position = "fixed";
    zone.style.top = "0";
    zone.style.left = "-9999px";
    document.body.appendChild(zone);
    zone.select();
    zone.setSelectionRange(0, texte.length);
    const reussi = document.execCommand("copy");
    document.body.removeChild(zone);
    return reussi;
  } catch (e) {
    return false;
  }
}

async function copier(texte, bouton, label) {
  const etiquette = bouton.querySelector("span");
  const statut = $("copy-status");
  const reussi = await ecrireDansPressePapiers(texte);

  if (reussi) {
    bouton.classList.add("is-copied");
    etiquette.textContent = "Copié";
    if (statut) statut.textContent = "Correctif " + label + " copié dans le presse-papiers.";
  } else {
    etiquette.textContent = "Échec";
    if (statut) statut.textContent = "La copie a échoué. Sélectionnez le texte manuellement.";
  }

  setTimeout(() => {
    bouton.classList.remove("is-copied");
    etiquette.textContent = "Copier";
  }, 1800);
}

/* ═══════════════════════════════════════════════════════════════
   8. Demarrage commun
   ═══════════════════════════════════════════════════════════════ */

initialiserTheme();
