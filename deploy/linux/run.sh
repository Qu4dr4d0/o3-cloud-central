#!/bin/sh
set -eu
exec /usr/bin/env -i HOME=/var/lib/o3cloudcentral-agent PATH=/usr/bin:/bin PYTHONHOME=/opt/o3cloudcentral-agent/runtime LD_LIBRARY_PATH=/opt/o3cloudcentral-agent/runtime/lib PYTHONPATH=/opt/o3cloudcentral-agent/app PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 /opt/o3cloudcentral-agent/runtime/bin/python3.12 -B -m edgehub agent --config /var/lib/o3cloudcentral-agent/config.json
