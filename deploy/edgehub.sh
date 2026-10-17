#!/bin/sh
# PROVIDE: edgehub_compat
# REQUIRE: o3cloudcentral
# KEYWORD: nostart
# Legacy command only. Boot starts the canonical service exactly once.
exec /usr/local/etc/rc.d/o3cloudcentral.sh "$@"
