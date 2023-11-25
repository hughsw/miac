#!/bin/bash

# admin_pw2=$(podman run -it --rm --env TERM=screen.xterm-256color miac-flat ./test-dialog.sh)

set -euo pipefail

set -x

#admin_pw=$(podman run -it --rm --env TERM=screen.xterm-256color -v $miac_root:${storage_root} miac-flat setup/miac-conf.py $public_ip ${storage_root}/${miac_env} 3>&2 2>&1 1>&3)
admin_pw=$(setup/miac-conf.py 1.2.3.4 /tmp/test-dialog-env 3>&2 2>&1 1>&3)
echo admin_pw: "$admin_pw" 1>&2
