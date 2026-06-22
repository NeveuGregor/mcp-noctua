"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
from .errors import CommandRejected

# Workflows bornes : ils enchainent des outils cote Python (pas de shell), avec
# des limites de debit/concurrence pour rester polis avec la cible.


def _check_arg(value: str, label: str) -> str:
    """Rejette les entrees vides ou pouvant etre prises pour un flag."""
    if not value or not value.strip():
        raise CommandRejected(f"{label} vide")
    v = value.strip()
    if v.startswith("-"):
        raise CommandRejected(f"{label} invalide (ne peut commencer par '-') : {v!r}")
    return v


def _check_url(url: str) -> str:
    u = _check_arg(url, "url")
    if not u.startswith(("http://", "https://")):
        raise CommandRejected(f"url doit commencer par http:// ou https:// : {u!r}")
    return u


def _clamp(value, lo, hi):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return lo
    return max(lo, min(value, hi))


def web_crawl(toolbox, url: str, depth: int = 1, timeout: int = 120) -> dict:
    """Crawl borne (katana) : profondeur 1..3, JS crawling actif."""
    url = _check_url(url)
    depth = _clamp(depth, 1, 3)
    argv = ["katana", "-u", url, "-d", str(depth), "-jc", "-silent"]
    res = toolbox.exec(argv, timeout)
    res["command"] = " ".join(argv)
    return res


def port_scan(toolbox, target: str, top_ports: int = 100, timeout: int = 300) -> dict:
    """Scan de ports (naabu) puis sonde HTTP (httpx) des ports ouverts."""
    target = _check_arg(target, "target")
    top_ports = _clamp(top_ports, 1, 65535)
    naabu_argv = ["naabu", "-host", target, "-top-ports", str(top_ports), "-silent"]
    naabu = toolbox.exec(naabu_argv, timeout)

    open_ports = [l.strip() for l in naabu["output"].splitlines() if ":" in l and l.strip()]
    httpx = None
    if open_ports:
        httpx_argv = [
            "httpx", "-silent", "-title", "-tech-detect", "-status-code",
            "-u", ",".join(open_ports),
        ]
        httpx = toolbox.exec(httpx_argv, min(timeout, 120))

    return {
        "target": target,
        "open_ports": open_ports,
        "naabu": naabu,
        "httpx": httpx,
    }


def vuln_scan(toolbox, url: str, tags: str = "", severity: str = "", timeout: int = 900) -> dict:
    """Scan de vulnerabilites borne (nuclei) : debit et concurrence limites."""
    url = _check_url(url)
    argv = ["nuclei", "-u", url, "-rl", "50", "-c", "25", "-timeout", "10", "-silent"]
    if tags and tags.strip():
        t = tags.strip()
        if not all(c.isalnum() or c in ",-_" for c in t):
            raise CommandRejected(f"tags invalides : {t!r}")
        argv += ["-tags", t]
    if severity and severity.strip():
        s = severity.strip()
        if not all(c.isalnum() or c in ",-" for c in s):
            raise CommandRejected(f"severity invalide : {s!r}")
        argv += ["-severity", s]
    res = toolbox.exec(argv, timeout)
    res["command"] = " ".join(argv)
    return res
