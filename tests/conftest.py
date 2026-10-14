"""
Outils communs aux tests : DNS factice et serveur HTTP local.

Tous les tests sont hors ligne : socket.getaddrinfo est remplacé pour
toute la session de test. Seuls les noms déclarés dans la table du DNS
factice et les adresses IP saisies directement sont résolus ; tout autre
nom est « introuvable ».
"""

import ipaddress
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# Le dossier du projet doit être importable (app, moteur, reseau…).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _entree(adresse, port):
    ip = ipaddress.ip_address(adresse)
    if ip.version == 4:
        return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (adresse, port))
    return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (adresse, port, 0, 0))


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    """Table nom -> liste d'adresses, modifiable par chaque test."""
    table = {}

    def faux_getaddrinfo(hote, port, *args, **kwargs):
        if isinstance(hote, bytes):
            hote = hote.decode("ascii")
        port = int(port or 0)
        if hote in table:
            return [_entree(a, port) for a in table[hote]]
        try:
            ipaddress.ip_address(hote)
        except ValueError:
            raise socket.gaierror(socket.EAI_NONAME, "nom introuvable (DNS factice)")
        return [_entree(hote, port)]

    monkeypatch.setattr(socket, "getaddrinfo", faux_getaddrinfo)
    return table


@pytest.fixture(autouse=True)
def base_historique(tmp_path, monkeypatch):
    """Chaque test écrit dans sa propre base d'historique, jamais dans instance/."""
    import historique
    monkeypatch.setattr(historique, "_chemin", None)
    return historique.initialiser(str(tmp_path / "historique.db"))


class ServeurLocal:
    """Serveur HTTP dans un thread ; routes : chemin -> (code, en-têtes, corps)."""

    def __init__(self, routes):
        self.routes = routes
        self.chemins_demandes = []
        serveur = self

        class Gestionnaire(BaseHTTPRequestHandler):
            def do_GET(self):
                # Derrière un mandataire, le chemin est une URL absolue.
                chemin = self.path
                serveur.chemins_demandes.append(chemin)
                code, entetes, corps = serveur.routes.get(
                    chemin, serveur.routes.get("*", (404, {}, b"introuvable")))
                self.send_response(code)
                for nom, valeur in entetes.items():
                    self.send_header(nom, valeur.format(port=serveur.port))
                self.send_header("Content-Length", str(len(corps)))
                self.end_headers()
                self.wfile.write(corps)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Gestionnaire)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def arreter(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serveur_local():
    """Fabrique de serveurs locaux, arrêtés à la fin du test."""
    serveurs = []

    def fabriquer(routes):
        s = ServeurLocal(routes)
        serveurs.append(s)
        return s

    yield fabriquer
    for s in serveurs:
        s.arreter()
