"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import json

import pytest

from src.server import NoctuaServer


class _FakeToolbox:
    def __init__(self):
        self.calls = []

    def exec(self, argv, timeout):
        self.calls.append((argv, timeout))
        return {"exit_code": 0, "output": "ok", "timed_out": False, "truncated": False}

    def list_available(self, names):
        return {"present": ["httpx"], "absent": []}

    def health(self):
        return {"container": "darkmoon", "present": True, "status": "running"}


def _text(res):
    assert len(res) == 1
    return res[0].text


async def test_run_tool_appelle_exec_avec_argv():
    tb = _FakeToolbox()
    srv = NoctuaServer(toolbox=tb)
    res = await srv._invoke("run_tool", {"command": "httpx -u http://x"})
    out = json.loads(_text(res))
    assert tb.calls[0][0] == ["httpx", "-u", "http://x"]
    assert out["exit_code"] == 0
    assert out["command"] == "httpx -u http://x"


async def test_run_tool_timeout_clamp():
    tb = _FakeToolbox()
    srv = NoctuaServer(toolbox=tb)
    await srv._invoke("run_tool", {"command": "nuclei -u http://x", "timeout": 99999})
    assert tb.calls[0][1] == 3600  # plafonne a _MAX_TIMEOUT


async def test_run_tool_commande_rejetee():
    srv = NoctuaServer(toolbox=_FakeToolbox())
    res = await srv._invoke("run_tool", {"command": "bash -c id"})
    assert "non autorise" in _text(res)


async def test_tool_inconnu():
    srv = NoctuaServer(toolbox=_FakeToolbox())
    res = await srv._invoke("inexistant", {})
    assert "inconnu" in _text(res)


async def test_health():
    srv = NoctuaServer(toolbox=_FakeToolbox())
    out = json.loads(_text(await srv._invoke("health", {})))
    assert out["status"] == "running"


async def test_list_tools_definitions():
    srv = NoctuaServer(toolbox=_FakeToolbox())
    names = {t.name for t in srv._tool_defs()}
    assert names == {"run_tool", "web_crawl", "port_scan", "vuln_scan", "list_tools", "health"}


async def test_vuln_scan_via_invoke():
    tb = _FakeToolbox()
    srv = NoctuaServer(toolbox=tb)
    await srv._invoke("vuln_scan", {"url": "http://x", "severity": "high,critical"})
    argv = tb.calls[0][0]
    assert argv[:3] == ["nuclei", "-u", "http://x"]
    assert "-severity" in argv and "high,critical" in argv
