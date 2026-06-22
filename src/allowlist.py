"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import shlex
from pathlib import PurePosixPath

from .errors import CommandRejected

# Outils autorises (si presents dans la toolbox). Centre sur la
# reconnaissance, l'enumeration et la validation de vulnerabilites.
# Volontairement HORS liste : brute-force / crackage (hydra, medusa, john,
# hashcat) et frameworks d'exploitation (msfconsole) -> chaines offensives
# lourdes, hors scope v1 et susceptibles de declencher les classifiers.
ALLOWED_TOOLS = frozenset({
    # decouverte reseau / ports
    "naabu", "nmap", "masscan",
    # web / HTTP
    "httpx", "curl", "whatweb", "wafw00f",
    # crawl / collecte d'URLs
    "katana", "gospider", "hakrawler", "gau", "waybackurls",
    # enumeration de contenu
    "ffuf", "gobuster", "feroxbuster", "dirb",
    # scan de vulnerabilites
    "nuclei", "nikto", "wpscan", "dalfox", "sqlmap",
    # DNS / sous-domaines
    "subfinder", "dnsx", "amass", "dnsrecon", "dig", "host", "nslookup",
    # TLS
    "sslscan", "testssl.sh",
    # parametres caches
    "arjun",
})

# Filet de securite (defense en profondeur). En forme exec sans shell ces
# motifs ne peuvent de toute facon pas chainer une commande, mais on rejette
# tout argv qui les contiendrait par accident de construction.
BLOCKED_SUBSTRINGS = (
    "rm -rf",
    ":(){",          # fork bomb
    "mkfs",
    "dd if=",
    "/dev/sd",
    "shutdown",
    "reboot",
    "> /dev/",
)


def parse_and_validate(command: str) -> list[str]:
    """Analyse une commande en argv et valide l'outil contre l'allow-list.

    Retourne la liste argv prete pour un exec sans shell. Leve CommandRejected
    si la commande est vide, non analysable, contient un motif interdit, ou
    invoque un binaire non autorise.
    """
    if command is None or not command.strip():
        raise CommandRejected("commande vide")

    low = command.lower()
    for pat in BLOCKED_SUBSTRINGS:
        if pat in low:
            raise CommandRejected(f"motif interdit detecte : {pat!r}")

    try:
        argv = shlex.split(command)
    except ValueError as e:
        raise CommandRejected(f"commande non analysable : {e}")

    if not argv:
        raise CommandRejected("commande vide apres analyse")

    binary = PurePosixPath(argv[0]).name
    if binary not in ALLOWED_TOOLS:
        raise CommandRejected(f"outil non autorise : {binary}")

    # Normalise argv[0] sur le seul nom de binaire (pas de chemin absolu force).
    argv[0] = binary
    return argv
