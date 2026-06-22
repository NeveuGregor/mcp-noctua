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
from . import workflows

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
                name="web_crawl",
                description="Crawl borne d'une URL (katana, profondeur 1..3, crawling JS).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL http(s) de depart."},
                        "depth": {"type": "integer", "description": "Profondeur 1..3 (defaut 1)."},
                        "timeout": {"type": "integer", "description": "Timeout en secondes (defaut 120)."},
                    },
                    "required": ["url"],
                },
            ),
            types.Tool(
                name="port_scan",
                description="Scan de ports (naabu top-ports) puis sonde HTTP (httpx) des ports ouverts.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Hote ou IP cible."},
                        "top_ports": {"type": "integer", "description": "Nombre de top-ports (defaut 100)."},
                        "timeout": {"type": "integer", "description": "Timeout en secondes (defaut 300)."},
                    },
                    "required": ["target"],
                },
            ),
            types.Tool(
                name="vuln_scan",
                description="Scan de vulnerabilites borne (nuclei) : debit/concurrence limites, tags et severite optionnels.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL http(s) cible."},
                        "tags": {"type": "string", "description": "Tags nuclei, ex. 'cve,exposure' (optionnel)."},
                        "severity": {"type": "string", "description": "Severites, ex. 'high,critical' (optionnel)."},
                        "timeout": {"type": "integer", "description": "Timeout en secondes (defaut 900)."},
                    },
                    "required": ["url"],
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
            elif name == "web_crawl":
                result = await asyncio.to_thread(
                    workflows.web_crawl, self.toolbox,
                    arguments.get("url"),
                    arguments.get("depth", 1),
                    arguments.get("timeout", 120),
                )
            elif name == "port_scan":
                result = await asyncio.to_thread(
                    workflows.port_scan, self.toolbox,
                    arguments.get("target"),
                    arguments.get("top_ports", 100),
                    arguments.get("timeout", 300),
                )
            elif name == "vuln_scan":
                result = await asyncio.to_thread(
                    workflows.vuln_scan, self.toolbox,
                    arguments.get("url"),
                    arguments.get("tags", ""),
                    arguments.get("severity", ""),
                    arguments.get("timeout", 900),
                )
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
