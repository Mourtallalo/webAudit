"""
fiches.py
=========
Base de connaissances pedagogique du scanner.

Pour chaque controle effectue par les modules d'analyse, ce fichier
fournit l'explication destinee a l'utilisateur, le risque concret, et
le ou les correctifs a appliquer.

Ce fichier est l'unique source : l'interface web le recoit en JSON
(injecte dans la page par app.py) et le generateur de rapport PDF
l'importe directement. Une seule liste a tenir a jour.

Les cles correspondent exactement aux libelles produits par les
modules d'analyse : la cle "header" pour headers_analyzer, la cle
"critere" pour https_checker et cms_detector. Accents compris : un
libelle affiche a l'ecran sert aussi de cle ici, donc les deux doivent
etre modifies ensemble. La fonction verifier_couverture(), en bas de
ce fichier, controle que rien n'a ete oublie.

Auteur : Mourtalla LO
Memoire de fin de Licence 3 Reseaux et Telecommunications - ESTM 2025-2026
"""

RECHARGER_NGINX = "sudo nginx -t && sudo systemctl reload nginx"

# Avertissement placé en tête de chaque fiche d'en-tête (C25).
ADAPTER_EN_TETE = (
    "Exemple à adapter à votre hébergement et à votre site : sur Vercel, par "
    "exemple, l'en-tête se déclare dans le fichier vercel.json, et non dans "
    "Nginx ou Apache. Vérifiez ensuite que la politique ne bloque pas les "
    "services utilisés par le site (polices, statistiques, paiement, cartes…)."
)

FICHES = {
    "Content-Security-Policy": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Une liste blanche qui indique au navigateur les seules sources de "
                "scripts, de styles et d'images qu'il a le droit de charger sur vos pages.",
        "risque": "Sans elle, un script injecté — via un commentaire, un formulaire, ou "
                  "une extension tierce compromise — s'exécute avec les mêmes droits que "
                  "votre propre code : vol de cookie de session, faux formulaire de "
                  "connexion, redirection des visiteurs.",
        "fix": [
            {"label": "Nginx",
             "code": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; "
                     "style-src 'self'; img-src 'self' data:; object-src 'none'; "
                     "frame-ancestors 'self'; base-uri 'self'\" always;"},
            {"label": "Apache",
             "code": "Header always set Content-Security-Policy \"default-src 'self'; "
                     "script-src 'self'; style-src 'self'; img-src 'self' data:; "
                     "object-src 'none'; frame-ancestors 'self'; base-uri 'self'\""},
        ],
        "apres": RECHARGER_NGINX,
        "note": "À déployer progressivement : commencez par Content-Security-Policy-Report-Only "
                "pour repérer ce que la règle casserait, puis basculez.",
    },

    "Strict-Transport-Security": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Demande au navigateur de n'utiliser que HTTPS pour ce domaine pendant la "
                "durée indiquée, même si le visiteur tape l'adresse sans « https:// ».",
        "risque": "Sans HSTS, la première requête part en clair et peut être interceptée sur "
                  "un réseau Wi-Fi partagé : l'attaquant maintient la victime en HTTP et lit "
                  "tout ce qu'elle saisit (technique du SSL stripping).",
        "fix": [
            {"label": "Nginx",
             "code": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"},
            {"label": "Apache",
             "code": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""},
        ],
        "apres": RECHARGER_NGINX,
        "note": "N'activez includeSubDomains que si tous vos sous-domaines sont bien en HTTPS, "
                "sinon ils deviendront inaccessibles.",
    },

    "X-Frame-Options": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Interdit l'affichage de vos pages dans un cadre (iframe) depuis un autre site.",
        "risque": "Un site pirate superpose un cadre transparent de votre site au-dessus de ses "
                  "propres boutons : le visiteur croit cliquer chez lui, mais valide une action "
                  "chez vous — changement de mot de passe, virement, suppression "
                  "(détournement de clic).",
        "fix": [
            {"label": "Nginx", "code": "add_header X-Frame-Options \"SAMEORIGIN\" always;"},
            {"label": "Apache", "code": "Header always set X-Frame-Options \"SAMEORIGIN\""},
        ],
        "apres": RECHARGER_NGINX,
        "note": "La directive moderne équivalente est frame-ancestors dans "
                "Content-Security-Policy ; gardez les deux le temps que les anciens "
                "navigateurs disparaissent.",
    },

    "X-Content-Type-Options": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Force le navigateur à respecter le type de fichier déclaré par le serveur, "
                "au lieu de le deviner d'après son contenu.",
        "risque": "Un fichier téléversé par un visiteur et annoncé comme image peut être "
                  "réinterprété comme du JavaScript, donc exécuté dans le navigateur des "
                  "autres visiteurs.",
        "fix": [
            {"label": "Nginx", "code": "add_header X-Content-Type-Options \"nosniff\" always;"},
            {"label": "Apache", "code": "Header always set X-Content-Type-Options \"nosniff\""},
        ],
        "apres": RECHARGER_NGINX,
    },

    "Referrer-Policy": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Limite l'adresse de la page d'origine transmise aux sites externes lorsqu'un "
                "visiteur suit un lien sortant.",
        "risque": "Une URL interne — jeton de réinitialisation de mot de passe, identifiant de "
                  "commande, page d'administration — peut se retrouver dans les journaux d'un "
                  "site tiers, puis dans ses outils de statistiques.",
        "fix": [
            {"label": "Nginx", "code": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"},
            {"label": "Apache", "code": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""},
        ],
        "apres": RECHARGER_NGINX,
    },

    "Permissions-Policy": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Coupe l'accès aux fonctions sensibles du navigateur (caméra, micro, "
                "géolocalisation) pour tous les scripts de la page.",
        "risque": "Un script tiers compromis — régie publicitaire, outil de mesure d'audience — "
                  "peut demander la position ou la caméra du visiteur en votre nom, et sous "
                  "votre nom de domaine.",
        "fix": [
            {"label": "Nginx",
             "code": "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;"},
            {"label": "Apache",
             "code": "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\""},
        ],
        "apres": RECHARGER_NGINX,
        "note": "Si le site utilise la caméra (par exemple un lecteur de codes-barres), "
                "autorisez le site lui-même avec camera=(self) plutôt que camera=().",
    },

    "Server": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "L'en-tête Server annonce le logiciel qui sert vos pages, parfois avec son "
                "numéro de version exact.",
        "risque": "L'attaquant n'a plus à chercher : il cible directement les failles publiées "
                  "pour cette version précise, et sait quels exploits ont une chance d'aboutir.",
        "fix": [
            {"label": "Nginx — dans le bloc http", "code": "http {\n    server_tokens off;\n}"},
            {"label": "Apache — dans apache2.conf", "code": "ServerTokens Prod\nServerSignature Off"},
        ],
        "apres": RECHARGER_NGINX,
        "note": "Masquer la version ne corrige aucune faille : c'est une mesure de discrétion, "
                "à combiner avec les mises à jour.",
    },

    "X-Powered-By": {
        "adapter": ADAPTER_EN_TETE,
        "quoi": "Annonce le langage ou le cadriciel qui génère les pages (PHP, Express, "
                "ASP.NET), souvent avec sa version.",
        "risque": "Même mécanique que l'en-tête Server : la version exacte guide l'attaquant "
                  "vers les failles connues et les outils déjà écrits pour elles.",
        "fix": [
            {"label": "PHP — dans php.ini", "code": "expose_php = Off"},
            {"label": "Nginx — en frontal d'un applicatif", "code": "proxy_hide_header X-Powered-By;"},
        ],
        "apres": "sudo systemctl reload php8.2-fpm && " + RECHARGER_NGINX,
    },

    "Disponibilité HTTPS": {
        "quoi": "HTTPS chiffre les échanges entre le visiteur et le serveur, et garantit "
                "qu'ils n'ont pas été modifiés en route.",
        "risque": "En HTTP simple, tout ce qui transite est lisible et modifiable par quiconque "
                  "partage le réseau : identifiants, contenu des formulaires, cookies de "
                  "session. Un intermédiaire peut aussi injecter du code dans vos pages.",
        "fix": [
            {"label": "Certificat gratuit Let's Encrypt",
             "code": "sudo apt install certbot python3-certbot-nginx\n"
                     "sudo certbot --nginx -d exemple.com -d www.exemple.com"},
        ],
        "note": "Certbot installe le certificat et configure le renouvellement automatique. "
                "Remplacez exemple.com par votre domaine.",
    },

    "Validité du certificat": {
        "quoi": "Le certificat prouve que le domaine visité est bien le vôtre. Il porte une "
                "date d'expiration, généralement 90 jours pour Let's Encrypt.",
        "risque": "Un certificat expiré déclenche un avertissement plein écran : les visiteurs "
                  "partent, et les intégrations automatisées (paiement, API, applications "
                  "mobiles) cessent de fonctionner sans prévenir.",
        "fix": [
            {"label": "Vérifier le renouvellement automatique",
             "code": "sudo certbot renew --dry-run\nsystemctl status certbot.timer"},
        ],
        "note": "Si le minuteur est inactif, activez-le avec : "
                "sudo systemctl enable --now certbot.timer",
    },

    "Version du protocole TLS": {
        "quoi": "La version du protocole de chiffrement négociée entre le navigateur et "
                "votre serveur.",
        "risque": "TLS 1.0 et 1.1 ont des faiblesses documentées (BEAST, Lucky13) et sont "
                  "refusés par les navigateurs récents : au mieux vos visiteurs voient une "
                  "erreur, au pire la connexion est déchiffrable.",
        "fix": [
            {"label": "Nginx", "code": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;"},
            {"label": "Apache", "code": "SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLHonorCipherOrder off"},
        ],
        "apres": RECHARGER_NGINX,
    },

    "Redirection HTTP vers HTTPS": {
        "quoi": "Une redirection permanente qui renvoie toute visite arrivée en HTTP vers "
                "l'adresse HTTPS équivalente.",
        "risque": "Sans elle, la version non chiffrée du site reste accessible et indexable : "
                  "un visiteur qui tape l'adresse sans « https:// » saisit ses identifiants en "
                  "clair, même si le site sait faire du HTTPS.",
        "fix": [
            {"label": "Nginx",
             "code": "server {\n    listen 80;\n    listen [::]:80;\n"
                     "    server_name exemple.com www.exemple.com;\n"
                     "    return 301 https://$host$request_uri;\n}"},
            {"label": "Apache — dans le VirtualHost du port 80",
             "code": "RewriteEngine On\nRewriteCond %{HTTPS} off\n"
                     "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"},
        ],
        "apres": RECHARGER_NGINX,
    },

    "Identification du CMS": {
        "quoi": "Les chemins de fichiers et les balises laissées dans le code source révèlent "
                "quel système de gestion de contenu fait tourner le site.",
        "risque": "Connaître le CMS permet de lancer directement les outils spécialisés "
                  "(wpscan, droopescan) et de dérouler la liste des failles de ses extensions, "
                  "sans phase de reconnaissance.",
        "fix": [
            {"label": "WordPress — dans functions.php du thème",
             "code": "remove_action('wp_head', 'wp_generator');\n"
                     "add_filter('the_generator', '__return_empty_string');"},
        ],
        "note": "Un CMS non identifiable n'est ni bon ni mauvais en soi : c'est une gêne pour "
                "l'attaquant, pas une protection. Les mises à jour restent l'essentiel.",
    },

    "Version du CMS": {
        "quoi": "Le numéro de version exact du CMS, souvent laissé dans une balise meta ou "
                "dans l'adresse des scripts chargés.",
        "risque": "Une version obsolète a des failles publiées, avec un code d'exploitation "
                  "déjà disponible. Des robots balayent le web en continu à la recherche "
                  "précisément de ces versions : l'attaque n'est pas ciblée, elle est "
                  "automatique.",
        "fix": [
            {"label": "WordPress — avec WP-CLI",
             "code": "wp core update\nwp plugin update --all\nwp theme update --all"},
            {"label": "Sauvegarde avant mise à jour",
             "code": "wp db export sauvegarde-$(date +%F).sql"},
        ],
        "note": "Sauvegardez la base et les fichiers avant toute mise à jour majeure, puis "
                "vérifiez le site page par page.",
    },
}


# Noms d'affichage des modules, partages par l'interface et le PDF.
NOMS_MODULES = {
    "En-tetes HTTP": "En-têtes HTTP de sécurité",
    "HTTPS / TLS": "HTTPS et certificat TLS",
    "Detection CMS": "Détection du CMS",
}


def fiche_pour(observation):
    """
    Retourne la fiche correspondant a une observation, ou None.

    Une observation porte son libelle dans "header" (module en-tetes)
    ou dans "critere" (modules HTTPS et CMS).
    """
    libelle = observation.get("header") or observation.get("critere")
    return FICHES.get(libelle)


def libelles_sans_fiche(resultats):
    """
    Liste les libelles non conformes qui n'ont pas de fiche associee.

    Sert de garde-fou : le libelle affiche a l'ecran est aussi la cle
    de ce fichier, donc une correction de texte faite ici ou dans un
    module d'analyse sans l'autre casse silencieusement l'affichage du
    correctif. Passer le resultat d'un scan a cette fonction le
    signale tout de suite.

    Retour
    ------
    list : les libelles orphelins, tries et dedoublonnes.
    """
    manquants = set()
    for module in resultats:
        for observation in module.get("observations", []):
            if observation.get("niveau") == "OK":
                continue
            libelle = observation.get("header") or observation.get("critere")
            if libelle and libelle not in FICHES:
                manquants.add(libelle)
    return sorted(manquants)


def verifier_couverture_headers():
    """
    Controle que chaque en-tete surveille par headers_analyzer a sa fiche.

    Seul ce module expose la liste de ce qu'il verifie. Les criteres de
    https_checker et cms_detector dependent de la reponse de la cible :
    pour ceux-la, utilisez libelles_sans_fiche() sur un resultat de scan.

    Retour
    ------
    list : les en-tetes sans fiche, tries.
    """
    from headers_analyzer import SECURITY_HEADERS

    attendus = set(SECURITY_HEADERS) | {"Server", "X-Powered-By"}
    return sorted(attendus - set(FICHES))
