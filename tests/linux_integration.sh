#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${1:-python3}
# All mutations run in child user + mount + network namespaces. /run is private too.
exec unshare --user --map-root-user --mount --net sh -eu -c '
  mount --make-rprivate /
  mount -t tmpfs -o mode=755 tmpfs /run
  export OBW_PRIVATE_TEST=1
  exec "$1" "$2/linux_integration.py"
' sh "$PYTHON" "$SCRIPT_DIR"
