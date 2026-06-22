"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import pytest

from src.allowlist import parse_and_validate
from src.errors import CommandRejected


def test_outil_autorise_simple():
    assert parse_and_validate("httpx -u http://localhost") == ["httpx", "-u", "http://localhost"]


def test_url_avec_esperluette_preservee():
    # `&` dans une URL est un argument litteral, pas un operateur shell.
    argv = parse_and_validate('curl "http://localhost/pmb/index.php?lvl=search&id=1"')
    assert argv == ["curl", "http://localhost/pmb/index.php?lvl=search&id=1"]


def test_chemin_absolu_normalise_sur_le_binaire():
    assert parse_and_validate("/usr/bin/nuclei -u http://x")[0] == "nuclei"


def test_outil_non_autorise_rejete():
    with pytest.raises(CommandRejected, match="non autorise"):
        parse_and_validate("bash -c whoami")


def test_chainage_par_outil_non_autorise():
    # Sans shell, `|` est un token litteral -> le binaire reste 'naabu',
    # mais la cible 'sh'/'cat' n'est jamais atteinte. On verifie surtout
    # qu'un binaire interdit en tete est rejete.
    with pytest.raises(CommandRejected):
        parse_and_validate("sh -c 'naabu -host x'")


@pytest.mark.parametrize("cmd", ["", "   ", None])
def test_commande_vide_rejetee(cmd):
    with pytest.raises(CommandRejected):
        parse_and_validate(cmd)


@pytest.mark.parametrize("cmd", [
    "curl http://x; rm -rf /",
    "nuclei && rm -rf .",
    "naabu :(){ :|:& };:",
])
def test_motifs_dangereux_rejetes(cmd):
    with pytest.raises(CommandRejected):
        parse_and_validate(cmd)


def test_guillemets_non_fermes_rejetes():
    with pytest.raises(CommandRejected, match="non analysable"):
        parse_and_validate('curl "http://x')
