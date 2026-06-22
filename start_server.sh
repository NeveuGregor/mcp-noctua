#!/usr/bin/env bash
#
# This file is part of mcp-noctua.
#
# mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.
#
# @author    Neveu Gregor <contact.neveugregor@proton.me>
# @copyright 2026 Neveu Gregor
# @license   CeCILL-B Free Software License Agreement
#
# Governed by the CeCILL-B license under French law - http://www.cecill.info
#
# Lanceur stdio pour mcp-noctua. IMPORTANT : aucune ecriture sur stdout
# (le protocole MCP transite par stdout) -> tout diagnostic va sur stderr.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "[noctua] venv absent : python3 -m venv venv && venv/bin/pip install -e ." >&2
  exit 1
fi
if [ ! -f .env ]; then
  echo "[noctua] .env absent : cp .env.example .env" >&2
  exit 1
fi

exec venv/bin/python -m src.main
