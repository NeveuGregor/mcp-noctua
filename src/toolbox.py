"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
import logging
import subprocess

import docker
from docker.errors import APIError, DockerException, NotFound

from .config import config
from .errors import ToolboxError

logger = logging.getLogger("noctua")

# SIGTERM puis SIGKILL apres ce delai de grace : garantit qu'aucun process ne
# survit au timeout (corrige le defaut Darkmoon de l'orphelin post-timeout).
_KILL_AFTER = "5"
# Plafond de sortie renvoyee a l'operateur (octets), pour ne pas noyer le contexte.
_MAX_OUTPUT = 100_000


class Toolbox:
    """Passerelle vers le conteneur toolbox : demarrage a la demande + exec borne."""

    def __init__(self, client=None, name=None, toolbox_compose=None):
        self._client = client
        self.name = name or config.docker_container_name
        self.toolbox_compose = (
            toolbox_compose if toolbox_compose is not None else config.noctua_toolbox_compose
        )

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as e:
                raise ToolboxError(f"client Docker indisponible : {e}")
        return self._client

    def _get_container(self):
        try:
            return self.client.containers.get(self.name)
        except NotFound:
            return None
        except APIError as e:
            raise ToolboxError(f"erreur Docker : {e}")

    def ensure_running(self) -> str:
        """Garantit que la toolbox tourne. Retourne 'running', 'started' ou leve.

        - conteneur deja up           -> 'running'
        - conteneur present mais arrete -> start() -> 'started'
        - conteneur absent             -> `docker compose up -d` si possible -> 'started'
        """
        container = self._get_container()
        if container is not None:
            if container.status == "running":
                return "running"
            logger.info("toolbox %s arretee (%s) -> demarrage", self.name, container.status)
            try:
                container.start()
            except APIError as e:
                raise ToolboxError(f"echec du demarrage de {self.name} : {e}")
            return "started"

        # Conteneur absent : le (re)creer via le compose embarque de noctua
        # (image publique ascit/darkmoon). Aucune dependance au depot Darkmoon.
        from pathlib import Path

        if not self.toolbox_compose or not Path(self.toolbox_compose).is_file():
            raise ToolboxError(
                f"conteneur '{self.name}' introuvable et compose toolbox absent "
                f"({self.toolbox_compose!r})"
            )
        logger.info("conteneur %s absent -> docker compose up -d (%s)", self.name, self.toolbox_compose)
        try:
            subprocess.run(
                ["docker", "compose", "-f", self.toolbox_compose, "up", "-d"],
                check=True,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            raise ToolboxError(f"echec de `docker compose up -d` : {e}")
        if self._get_container() is None:
            raise ToolboxError(f"conteneur '{self.name}' toujours absent apres compose up")
        return "started"

    def exec(self, argv: list[str], timeout: int) -> dict:
        """Execute argv dans la toolbox, sans shell, borne par `timeout`.

        Le binaire `timeout` du conteneur envoie SIGTERM puis SIGKILL : le
        process ne survit jamais au depassement. Retourne un dict avec
        exit_code, output (tronquee), timed_out, truncated.
        """
        self.ensure_running()
        container = self._get_container()
        if container is None:
            raise ToolboxError(f"conteneur '{self.name}' indisponible apres ensure_running")

        wrapped = ["timeout", "--kill-after", _KILL_AFTER, str(timeout), *argv]
        try:
            res = container.exec_run(wrapped, stdout=True, stderr=True, demux=False)
        except APIError as e:
            raise ToolboxError(f"echec de l'exec dans {self.name} : {e}")

        raw = res.output or b""
        text = raw.decode("utf-8", errors="replace")
        truncated = len(text) > _MAX_OUTPUT
        if truncated:
            text = text[:_MAX_OUTPUT] + "\n[... sortie tronquee ...]"

        # `timeout` : 124 = SIGTERM apres delai, 137 = 128+9 SIGKILL.
        timed_out = res.exit_code in (124, 137)
        return {
            "exit_code": res.exit_code,
            "output": text,
            "timed_out": timed_out,
            "truncated": truncated,
        }

    def health(self) -> dict:
        """Etat de la toolbox sans rien demarrer (pour diagnostic)."""
        container = self._get_container()
        if container is None:
            return {"container": self.name, "present": False, "status": "absent"}
        return {
            "container": self.name,
            "present": True,
            "status": container.status,
            "image": container.image.tags[0] if container.image.tags else container.image.short_id,
            "id": container.short_id,
        }
