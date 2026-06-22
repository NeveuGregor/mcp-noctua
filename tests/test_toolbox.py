"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
from types import SimpleNamespace

import pytest
from docker.errors import NotFound

from src.errors import ToolboxError
from src.toolbox import Toolbox


class _ExecResult(SimpleNamespace):
    pass


class _FakeContainer:
    def __init__(self, status="running"):
        self.status = status
        self.short_id = "abc123"
        self.image = SimpleNamespace(tags=["ascit/darkmoon:latest"], short_id="img1")
        self.started = False
        self.last_cmd = None

    def start(self):
        self.started = True
        self.status = "running"

    def exec_run(self, cmd, **kw):
        self.last_cmd = cmd
        return _ExecResult(exit_code=0, output=b"hello")


class _FakeClient:
    def __init__(self, container=None, missing=False):
        self._container = container
        self._missing = missing
        self.containers = SimpleNamespace(get=self._get)

    def _get(self, name):
        if self._missing:
            raise NotFound("absent")
        return self._container


def _toolbox(container=None, missing=False, compose_dir=""):
    return Toolbox(client=_FakeClient(container, missing), name="darkmoon", compose_dir=compose_dir)


def test_ensure_running_deja_up():
    tb = _toolbox(_FakeContainer("running"))
    assert tb.ensure_running() == "running"


def test_ensure_running_demarre_si_arrete():
    c = _FakeContainer("exited")
    tb = _toolbox(c)
    assert tb.ensure_running() == "started"
    assert c.started is True


def test_ensure_running_absent_sans_compose_dir_leve():
    tb = _toolbox(missing=True, compose_dir="")
    with pytest.raises(ToolboxError, match="introuvable"):
        tb.ensure_running()


def test_exec_enveloppe_avec_timeout():
    c = _FakeContainer("running")
    tb = _toolbox(c)
    res = tb.exec(["httpx", "-u", "http://x"], timeout=42)
    assert c.last_cmd[:4] == ["timeout", "--kill-after", "5", "42"]
    assert c.last_cmd[4:] == ["httpx", "-u", "http://x"]
    assert res["exit_code"] == 0
    assert res["output"] == "hello"
    assert res["timed_out"] is False


def test_exec_detecte_timeout():
    class _C(_FakeContainer):
        def exec_run(self, cmd, **kw):
            return _ExecResult(exit_code=124, output=b"")

    tb = _toolbox(_C("running"))
    assert tb.exec(["nuclei", "-u", "http://x"], timeout=1)["timed_out"] is True


def test_health_absent():
    tb = _toolbox(missing=True)
    h = tb.health()
    assert h == {"container": "darkmoon", "present": False, "status": "absent"}


def test_health_present():
    tb = _toolbox(_FakeContainer("running"))
    h = tb.health()
    assert h["present"] is True
    assert h["status"] == "running"
    assert h["image"] == "ascit/darkmoon:latest"
