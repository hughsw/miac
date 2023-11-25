#!/bin/bash

set -euo pipefail

# MIAC TODO: figure out how to manage env at various levels...
MIAC_SETUP_DIR=miac

source $MIAC_SETUP_DIR/miac-setup-vars.sh

source $venv/bin/activate
#export PYTHONPATH=$(pwd)/management

## MIAC TODO: figure out how to manage env...
#export PUBLIC_IP=$(curl -sS -4 --fail --silent --max-time 15 ipv4.icanhazip.com 2>/dev/null || /bin/true)

exec $MIAC_SETUP_DIR/miac-conf.py "$@"


## MIAC_GENERIC_STORAGE_ROOT=/home/miac/generic-user-data
## STORAGE_ROOT=/home/user-data
## MIAC_ENV
#
#rsync -a $MIAC_GENERIC_STORAGE_ROOT $STORAGE_ROOT
#
## https://ipv4.icanhazip.com/   https://ipv6.icanhazip.com/
#public_ip=$(curl -sS -4 --fail --silent --max-time 15 ipv4.icanhazip.com 2>/dev/null || /bin/true)
#
#setup/miac-conf.py $public_ip $STORAGE_ROOT/$MIAC_ENV
####admin_pw=$(podman run -it --rm --env TERM=screen.xterm-256color -v $miac_root:${storage_root} miac-flat $MIAC_SETUP_DIR/miac-conf.py $public_ip ${storage_root}/${miac_env} 3>&2 2>&1 1>&3)
