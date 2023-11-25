#!/bin/bash

set -euo pipefail
trap 'rc=$?;set +ex;if [[ $rc -ne 0 ]];then trap - ERR EXIT;echo 1>&2;echo "*** fail *** : code $rc : $DIR/$SCRIPT $ARGS" 1>&2;echo 1>&2;exit $rc;fi' ERR EXIT
ARGS="$*"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$(basename "${BASH_SOURCE[0]}")"

mkdir -p ${DIR}/miabtags
cd ${DIR}/miabtags

for tag in v60.1 v60 ; do
    echo $tag
    git clone -b $tag --depth 1 https://github.com/mail-in-a-box/mailinabox mailinabox-$tag < /dev/null
done
