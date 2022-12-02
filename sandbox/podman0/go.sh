#!/bin/bash

set -euo pipefail
trap 'rc=$?;set +ex;if [[ $rc -ne 0 ]];then trap - ERR EXIT;echo 1>&2;echo "*** fail *** : code $rc : $DIR/$SCRIPT $ARGS" 1>&2;echo 1>&2;exit $rc;fi' ERR EXIT
ARGS="$*"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$(basename "${BASH_SOURCE[0]}")"

set -x

cd $HOME/mailinabox

#git apply $HOME/system.patch
sed -i \
    -e 's|^rm -f /etc/resolv.conf$|echo > /etc/resolv.conf|' \
    setup/system.sh

sed -i \
    -e 's|^source setup/firstuser.sh$|#source setup/firstuser.sh|' \
    -e 's|Fingerprint=//"|Fingerprint=//i"|' \
    setup/start.sh

{
    source $HOME/mailinabox.env
    NONINTERACTIVE=1
    DEVBAILOUT=1
    source setup/start.sh
} 2>&1 | tee -a $HOME/start.log
