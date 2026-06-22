"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import asyncio
import json
import logging

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .allowlist import ALLOWED_TOOLS, parse_and_validate
from .config import config
from .errors import NoctuaError
from .toolbox import Toolbox

logger = logging.getLogger("noctua")

# Plafond dur sur le timeout demande par l'operateur (s).
_MAX_TIMEOUT = 3600


class NoctuaServer:
    """Serveur MCP stdio : expose la toolbox de pentest a l'orchestrateur LLM."""

    def __init__(self, toolbox=None):
        self.toolbox = toolbox or Toolbox()
        self.server = Server("noctua")
        self._register()

    def _register(self):
        @self.server.list_tools()
        async def _list_tools():
            return self._tool_defs()

        @self.server.call_tool()
        async def _call_tool(name, arguments):
            return await self._invoke(name, arguments or {})

    def _tool_defs(self):
        return [
            types.Tool(
                name="run_tool",
                description=(
                    "Execute un outil de reconnaissance/scan whiteliste dans la toolbox "
                    "(forme exec, sans shell : pas de pipe ni de chainage). Usage test "
                    "AUTORISE uniquement. Borne par un timeout qui tue reellement le "
                    "process. Pour enchainer des outils, faire plusieurs appels."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Commande complete, p.ex. 'httpx -u http://cible -title -tech-detect'.",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": f"Timeout en secondes (defaut {config.noctua_timeout}, max {_MAX_TIMEOUT}).",
                        },
                    },
                    "required": ["command"],
                },
            ),
            types.Tool(
                name="list_tools",
                description="Liste les outils whitelistes presents (et absents) dans la toolbox.",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="health",
                description="Etat du conteneur toolbox (present/absent, running, image). Ne demarre rien.",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    async def _invoke(self, name, arguments):
        try:
            if name == "run_tool":
                result = await self._run_tool(arguments)
            elif name == "list_tools":
                result = await asyncio.to_thread(self.toolbox.list_available, sorted(ALLOWED_TOOLS))
            elif name == "health":
                result = await asyncio.to_thread(self.toolbox.health)
            else:
                raise NoctuaError(f"tool inconnu : {name}")
            return [types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
        except NoctuaError as e:
            logger.warning("%s rejete : %s", name, e)
            return [types.TextContent(type="text", text=e.user_message())]

    async def _run_tool(self, arguments):
        argv = parse_and_validate(arguments.get("command"))
        timeout = arguments.get("timeout") or config.noctua_timeout
        try:
            timeout = max(1, min(int(timeout), _MAX_TIMEOUT))
        except (TypeError, ValueError):
            raise NoctuaError("timeout invalide")
        logger.info("run_tool %s (timeout=%ss)", argv, timeout)
        result = await asyncio.to_thread(self.toolbox.exec, argv, timeout)
        result["command"] = " ".join(argv)
        return result

    async def run(self):
        async with stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())
