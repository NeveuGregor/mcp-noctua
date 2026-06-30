# mcp-noctua

*🇬🇧 English · [🇫🇷 Français](README.fr.md)*

An MCP server (stdio) that exposes a **pentest toolbox** to a strong LLM
orchestrator (Claude Code, interactive), to run **authorized** security audits.

A clean rewrite inspired by the [Darkmoon](https://github.com/ASCIT31/Dark-Moon)
MCP (GPL v3) **with no code copied** → CeCILL-B license, zero GPL debt. What's
reused is the *toolbox* (sqlmap, nuclei, ffuf, httpx, naabu, katana, whatweb…);
the fragile orchestration (opencode + local model) is dropped and replaced by a
strong brain that **verifies**.

## Architecture

```
[Claude Code] --stdio--> [mcp-noctua (host)] --docker.sock--> [darkmoon container = toolbox]
   (the brain)             (controlled gateway)               (sqlmap, nuclei, ffuf…)
```

mcp-noctua **reuses** the `darkmoon` container (`ascit/darkmoon:latest`) as its
toolbox, invoking it via `docker.sock`. Invoking tools inside a container is not a
derivative work → no license concern. The container is kept alive; noctua starts
it if it's stopped before a run.

## Exposed MCP tools

| Tool | Role |
|------|------|
| `run_tool(command, timeout?)` | Run a **whitelisted** tool in the toolbox. |
| `web_crawl(url, depth?, timeout?)` | Bounded crawl (katana). |
| `port_scan(target, ...)` | naabu + httpx, bounded. |
| `vuln_scan(url, tags?)` | nuclei, bounded. |
| `list_tools()` | Tools available in the toolbox. |
| `health()` | Toolbox container state (running / started / not found). |

## Guard-rails

- Strict **allow-list** of tools; dangerous patterns blocked (`rm -rf`, fork bomb, exfil…).
- A timeout that **actually kills** the process inside the toolbox (fixes the Darkmoon flaw).
- **Authorized testing only**; the operator validates every target.

## Configuration (`.env`)

See `.env.example`. Keys: `DOCKER_CONTAINER_NAME`, `NOCTUA_TIMEOUT`,
`NOCTUA_REPORTS_DIR`, `NOCTUA_COMPOSE_DIR`, `DEBUG`.

## Install

```bash
git clone https://github.com/NeveuGregor/mcp-noctua.git
cd mcp-noctua
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # adjust as needed
pytest
```

Register in `~/.claude.json` as a stdio MCP server:
`venv/bin/python -m src.main` (cwd = `mcp-noctua`).

## License

CeCILL-B — see [LICENSE](LICENSE).
