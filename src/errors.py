"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""


class NoctuaError(Exception):
    """Erreur metier renvoyee a l'operateur (message lisible, sans stacktrace)."""

    def user_message(self) -> str:
        return f"[noctua] {self}"


class CommandRejected(NoctuaError):
    """La commande viole l'allow-list ou contient un pattern interdit."""


class ToolboxError(NoctuaError):
    """Probleme cote conteneur toolbox (absent, non demarrable, exec echoue)."""


class CommandTimeout(NoctuaError):
    """L'outil a depasse son timeout et a ete tue."""
