#!/bin/sh
set -e

/opt/stunnel/bin/stunnel /app/stunnel.conf &

exec /app/lfm
