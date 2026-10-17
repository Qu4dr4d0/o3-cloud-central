"""Windows product names. Legacy identifiers remain only for safe upgrades."""
from pathlib import Path
import os
import sys

PRODUCT_NAME = "O3 Cloud Central"
SERVICE_NAME = "O3CloudCentral"
EXECUTABLE_NAME = "O3CloudCentral.exe"
LEGACY_NAME = "EdgeHub"
LEGACY_EXECUTABLE_NAME = "EdgeHub.exe"
PIPE_NAME = r"\\.\pipe\EdgeHub.LocalControl.v1"  # Existing local protocol, not a display name.


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    configured = os.environ.get("EDGEHUB_RESOURCE_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[2]
