#!/bin/bash
# usage: tv.sh '<sdb args...>'  (one-shot: fresh container, connect, then run)
[ -z "$1" ] && { echo 'usage: tv.sh "<sdb args>"'; exit 1; }
docker run --platform linux/amd64 --rm -v "$(cd "$(dirname "$0")" && pwd):/w" -e SDBCMD="$1" ubuntu:24.04 bash -c '
/w/data/tools/sdb connect 192.168.0.85:26101
eval "/w/data/tools/sdb $SDBCMD"
'
