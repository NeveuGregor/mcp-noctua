# mcp-noctua

Serveur MCP (stdio) qui expose une **toolbox de pentest** à un orchestrateur LLM fort
(Claude Code, en mode interactif), pour mener des audits de sécurité **autorisés**.

Réécriture propre inspirée du MCP de [Darkmoon](https://github.com/ASCIT31/Dark-Moon)
(GPL v3) **sans copie de code** → licence CeCILL-B, zéro dette GPL. La valeur reprise
est la *toolbox* (sqlmap, nuclei, ffuf, httpx, naabu, katana, whatweb…) ; l'orchestration
fragile (opencode + modèle local) est jetée et remplacée par un cerveau fort qui **vérifie**.

## Architecture

```
[Claude Code] --stdio--> [mcp-noctua (hôte)] --docker.sock--> [conteneur darkmoon = toolbox]
   (cerveau)               (passerelle contrôlée)              (sqlmap, nuclei, ffuf…)
```

mcp-noctua **réutilise** le conteneur `darkmoon` (`ascit/darkmoon:latest`) comme toolbox :
il l'invoque via `docker.sock`. Invoquer des outils dans un conteneur n'est pas une œuvre
dérivée → aucun souci de licence. Le conteneur est gardé vivant ; noctua le démarre s'il
est arrêté avant un run.

## Outils MCP exposés

| Outil | Rôle |
|-------|------|
| `run_tool(command, timeout?)` | Exécute un outil **whitelisté** dans la toolbox. |
| `web_crawl(url, depth?, timeout?)` | Crawl borné (katana). |
| `port_scan(target, ...)` | naabu + httpx, borné. |
| `vuln_scan(url, tags?)` | nuclei borné. |
| `list_tools()` | Outils disponibles dans la toolbox. |
| `health()` | État du conteneur toolbox (running / démarré / introuvable). |

## Garde-fous

- **Allow-list** stricte d'outils ; patterns dangereux bloqués (`rm -rf`, fork bomb, exfil…).
- Timeout qui **tue réellement** le process dans la toolbox (corrige le défaut Darkmoon).
- Usage **test autorisé uniquement** ; l'opérateur valide chaque cible.

## Configuration (`.env`)

Voir `.env.example`. Clés : `DOCKER_CONTAINER_NAME`, `NOCTUA_TIMEOUT`,
`NOCTUA_REPORTS_DIR`, `NOCTUA_COMPOSE_DIR`, `DEBUG`.

## Installation

```bash
cd ~/script/Mcp/mcp-noctua
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # ajuster si besoin
pytest
```

Enregistrement dans `~/.claude.json` comme serveur MCP stdio :
`venv/bin/python -m src.main` (cwd = `mcp-noctua`).

## Licence

CeCILL-B — voir [LICENSE](LICENSE).
