"""
This file is part of mcp-noctua.

mcp-noctua - Serveur MCP de pentest : passerelle controlee vers une toolbox d'outils de securite.

@author    Neveu Gregor <contact.neveugregor@proton.me>
@copyright 2026 Neveu Gregor
@license   CeCILL-B Free Software License Agreement

Governed by the CeCILL-B license under French law - http://www.cecill.info
"""
from pathlib import Path

from dotenv import load_dotenv
from pydantic import field_validator
from pydantic_settings import BaseSettings

_PROJECT_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_DIR / ".env"
load_dotenv(_ENV_FILE)


class NoctuaConfig(BaseSettings):
    # Conteneur Docker servant de toolbox (reutilise l'image Darkmoon).
    docker_container_name: str = "darkmoon"
    # Timeout par defaut d'un outil, en secondes.
    noctua_timeout: int = 300
    # Repertoire de sortie des rapports rediges cote operateur.
    noctua_reports_dir: str = str(_PROJECT_DIR / "reports")
    # Compose embarque qui lance la toolbox (image publique ascit/darkmoon).
    # Utilise pour (re)creer le conteneur s'il est absent -> noctua reste
    # autonome, aucune dependance au depot git Darkmoon.
    noctua_toolbox_compose: str = str(_PROJECT_DIR / "docker-compose.toolbox.yml")
    debug: bool = False

    @field_validator("noctua_reports_dir")
    def _expand_reports(cls, v):
        return str(Path(v).expanduser())

    @field_validator("noctua_toolbox_compose")
    def _expand_compose(cls, v):
        # Valeur vide (ex. .env mal renseigne) -> on rebascule sur le defaut embarque.
        if not v or not v.strip():
            return str(_PROJECT_DIR / "docker-compose.toolbox.yml")
        return str(Path(v).expanduser())

    @field_validator("noctua_timeout")
    def _positive_timeout(cls, v):
        if v <= 0:
            raise ValueError("NOCTUA_TIMEOUT doit etre strictement positif")
        return v

    model_config = {"env_file": str(_ENV_FILE), "case_sensitive": False, "extra": "ignore"}


config = NoctuaConfig()
