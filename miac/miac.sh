#!/bin/bash

set -euo pipefail

set -x

export PRIMARY_HOSTNAME=shed.cochleaudio.com
export EMAIL_ADDR=me@cochleaudio.com
export EMAIL_PW=12345678

export NONINTERACTIVE=1
export SKIP_NETWORK_CHECKS=1
export DISABLE_FIREWALL=1

cd /home/miac/mailinabox

printenv
bash -x setup/start.sh 2>&1 | tee /miac/logs/start.log_$(date '+%Y-%m-%d-%H%M-%S')
