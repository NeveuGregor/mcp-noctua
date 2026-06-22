"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import pytest

from src import workflows
from src.errors import CommandRejected


class _FakeToolbox:
    def __init__(self, output=""):
        self.calls = []
        self._output = output

    def exec(self, argv, timeout):
        self.calls.append((argv, timeout))
        return {"exit_code": 0, "output": self._output, "timed_out": False, "truncated": False}


def test_web_crawl_clamp_profondeur():
    tb = _FakeToolbox()
    workflows.web_crawl(tb, "http://x", depth=99)
    argv = tb.calls[0][0]
    assert argv[:5] == ["katana", "-u", "http://x", "-d", "3"]


def test_web_crawl_url_invalide():
    with pytest.raises(CommandRejected, match="http"):
        workflows.web_crawl(_FakeToolbox(), "ftp://x")


def test_url_flag_injection_rejetee():
    with pytest.raises(CommandRejected):
        workflows.vuln_scan(_FakeToolbox(), "-u http://evil")


def test_port_scan_sonde_httpx_si_ports_ouverts():
    tb = _FakeToolbox(output="example.com:80\nexample.com:443\n")
    res = workflows.port_scan(tb, "example.com")
    assert res["open_ports"] == ["example.com:80", "example.com:443"]
    # 2 appels : naabu puis httpx
    assert len(tb.calls) == 2
    assert tb.calls[1][0][0] == "httpx"
    assert "example.com:80,example.com:443" in tb.calls[1][0]


def test_port_scan_pas_de_httpx_si_aucun_port():
    tb = _FakeToolbox(output="")
    res = workflows.port_scan(tb, "example.com")
    assert res["open_ports"] == []
    assert len(tb.calls) == 1  # naabu seul


def test_vuln_scan_tags_invalides():
    with pytest.raises(CommandRejected, match="tags"):
        workflows.vuln_scan(_FakeToolbox(), "http://x", tags="cve; rm -rf")
