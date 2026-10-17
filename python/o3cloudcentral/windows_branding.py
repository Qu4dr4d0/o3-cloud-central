"""Canonical Windows product and local control names."""
from pathlib import Path
import os
import sys

PRODUCT_NAME = "O3 Cloud Central"
SERVICE_NAME = "O3CloudCentral"
EXECUTABLE_NAME = "O3CloudCentral.exe"
PIPE_NAME = r"\\.\pipe\O3CloudCentral.LocalControl.v1"  # Existing local protocol, not a display name.


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    configured = os.environ.get("O3CLOUDCENTRAL_RESOURCE_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[2]
