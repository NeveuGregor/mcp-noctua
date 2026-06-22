"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import asyncio
import logging
import sys

from .config import config
from .server import NoctuaServer


def main():
    logging.basicConfig(
        level=logging.DEBUG if config.debug else logging.INFO,
        stream=sys.stderr,
    )
    try:
        asyncio.run(NoctuaServer().run())
    except KeyboardInterrupt:
        print("\nArret du serveur MCP noctua", file=sys.stderr)
    except Exception as e:
        print(f"Erreur: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
