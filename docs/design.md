# mcp-noctua — Design

**Date :** 2026-06-22
**Auteur :** Neveu Grégor
**Statut :** validé (design), avant implémentation

## But

Serveur MCP (FastMCP, Python, stdio) qui expose une **toolbox de pentest** à un
orchestrateur LLM fort (Claude Code en mode interactif), pour mener des audits de
sécurité **autorisés**. Réécriture propre, inspirée du MCP de Darkmoon (GPL v3) mais
**sans copie de code** → licence CeCILL-B, zéro dette GPL.

Motivation : le stack Darkmoon local (opencode + modèle local Ollama) s'est révélé
fragile (Ollama qui fige, verrou SQLite, wedge MCP) et le modèle local (qwen3-coder
30B) sur-cote/hallucine ses findings. La valeur réelle = la **toolbox** (sqlmap,
nuclei, ffuf, httpx, naabu, katana…) + une **passerelle contrôlée**. On garde ça,
on jette l'orchestration fragile, et on pilote avec un cerveau fort qui **vérifie**.

## Modèle d'opération : interactif

Claude Code = le cerveau. Boucle : planifier → appeler les outils noctua → **vérifier
les résultats (re-run ciblé)** → restituer *confirmé* vs *potentiel* → itérer avec
l'opérateur. Pas de run boîte-noire autonome. C'est là que le cerveau fort apporte
le plus : pas d'hallucination, findings prouvés.

## Architecture

```
[Claude Code] --stdio--> [mcp-noctua (FastMCP, hôte)] --docker.sock--> [conteneur darkmoon = toolbox]
   (cerveau)                (passerelle contrôlée)                       (sqlmap, nuclei, ffuf…)
```

1. **Toolbox** : conteneur `darkmoon` issu de l'**image publique** `ascit/darkmoon:latest`
   (Docker Hub, 50+ outils). L'image n'est PAS buildée depuis le dépôt git Darkmoon —
   elle est `docker pull`-able. Invoquer des outils dans un conteneur n'est PAS une
   œuvre dérivée → aucun souci de licence. noctua embarque son **propre**
   `docker-compose.toolbox.yml` (option B) qui lance cette image : il (re)crée le
   conteneur lui-même s'il est absent. **Portable** : un collègue clone mcp-noctua,
   l'image est pullée au premier run, aucune dépendance au dépôt git Darkmoon.
2. **mcp-noctua** : serveur FastMCP sur l'hôte, parle au conteneur via `docker.sock`
   (lib `docker`). Code neuf, CeCILL-B.
3. **Claude Code** : enregistré dans `~/.claude.json` comme MCP stdio
   (`venv/bin/python -m src.server`, cwd = `mcp-noctua`).

## Surface d'outils exposée (MCP tools)

- `run_tool(command, timeout?)` — exécute un outil **whitelisté** dans la toolbox.
  Garde-fous repris de Darkmoon : allow-list stricte (naabu, httpx, nuclei, ffuf,
  sqlmap, katana, whatweb, curl, …), patterns dangereux bloqués (`rm -rf`, fork bomb,
  exfil `wget http`…), timeout par défaut configurable.
- `web_crawl(url, depth=1, timeout=120)` — crawl borné (katana avec `-d` + timeout).
- `port_scan(target, ...)` — naabu + httpx, borné.
- `vuln_scan(url, tags?)` — nuclei borné (`-rl`, `-c`, `-timeout`, tags ciblés).
- `list_tools()` / `health()` — quels outils sont dispo dans la toolbox.

**Démarrage de la toolbox** : on garde le conteneur `darkmoon` vivant. Avant tout
appel d'outil, noctua **teste** que le conteneur tourne (`docker` status). S'il est
arrêté, il le **démarre** (`container.start()` si présent, sinon `docker compose up -d`
sur la stack Darkmoon) puis poursuit. `health()` renvoie l'état (running / démarré /
introuvable).

Volontairement **PAS repris** de Darkmoon : le dashboard/`live_push` (couplé à la DB
opencode), les 18 configs d'agents (le cerveau, c'est moi), le finalize_campaign.
Les rapports : je les rédige côté Claude Code à partir des sorties vérifiées, écrits
dans `NOCTUA_REPORTS_DIR`.

## Sécurité / scope

- **Allow-list d'outils** = garde-fou central, conservé.
- L'opérateur autorise explicitement chaque cible ; usage **test autorisé uniquement**.
- Reports en local (`NOCTUA_REPORTS_DIR`), rien n'est poussé ailleurs.

## Layout

```
~/script/Mcp/mcp-noctua/        (git privé)
  src/
    server.py        # FastMCP : déclare les tools, lance mcp.run()
    toolbox.py       # client docker → exec dans le conteneur, timeout, capture
    allowlist.py     # outils autorisés + patterns bloqués
    workflows.py     # web_crawl / port_scan / vuln_scan bornés
    config.py        # lecture .env (DOCKER_CONTAINER_NAME, NOCTUA_REPORTS_DIR, NOCTUA_TIMEOUT)
  tests/             # tests unitaires (allow-list, parsing, validation commande)
  venv/
  pyproject.toml  requirements.txt   (fastmcp, docker, pydantic, python-dotenv)
  .env / .env.example
  .gitignore  README.md  LICENSE (CeCILL-B)
  docs/design.md
```

En-tête CeCILL-B sur chaque fichier source (code from-scratch).

## Config (.env)

- `DOCKER_CONTAINER_NAME=darkmoon` — conteneur toolbox cible.
- `NOCTUA_TIMEOUT=300` — timeout par défaut d'un outil (s).
- `NOCTUA_REPORTS_DIR=~/script/Mcp/mcp-noctua/reports` — sortie des rapports.
- `NOCTUA_TOOLBOX_COMPOSE` — compose embarqué qui (re)crée la toolbox (défaut :
  `docker-compose.toolbox.yml` du projet ; ne PAS pointer le git Darkmoon).

## Plan d'implémentation (incrémental, testé à chaque étape)

1. Scaffold : `pyproject.toml`, `requirements.txt`, `.env.example`, `.gitignore`,
   `README.md`, venv, `git init` (privé).
2. `config.py` + `allowlist.py` (+ tests allow-list / patterns bloqués).
3. `toolbox.py` : exec dans le conteneur via lib `docker`, timeout **qui tue
   réellement** le process (corrige le défaut Darkmoon : l'orphelin après timeout).
4. `server.py` : `run_tool` + `list_tools`/`health`, `mcp.run()`. Test : appel réel
   d'un outil simple (ex. `httpx`) dans la toolbox.
5. `workflows.py` : `web_crawl` / `port_scan` / `vuln_scan` bornés.
6. Enregistrement dans `~/.claude.json`, validation de bout en bout (je pilote un
   mini-audit OPAC PMB en vérifiant chaque finding).

## Risques / limites connus

- Classifiers cyber d'Anthropic : peuvent interrompre certaines étapes offensives
  agressives même en contexte autorisé (Opus 4.8 concerné). Reco/identification/
  validation/reporting passent ; chaînes d'exploitation lourdes possiblement bloquées.
- Dépendance au conteneur `darkmoon` comme toolbox : si l'image disparaît, prévoir
  plus tard une toolbox maison (hors scope v1).
