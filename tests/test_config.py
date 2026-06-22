"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import pytest

from src.config import NoctuaConfig


def test_defauts():
    c = NoctuaConfig()
    assert c.docker_container_name == "darkmoon"
    assert c.noctua_timeout == 300


def test_reports_dir_expanduser():
    c = NoctuaConfig(noctua_reports_dir="~/x")
    assert not c.noctua_reports_dir.startswith("~")


def test_timeout_positif():
    with pytest.raises(ValueError):
        NoctuaConfig(noctua_timeout=0)
