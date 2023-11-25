#!/bin/bash

set -euo pipefail
trap 'rc=$?;set +ex;if [[ $rc -ne 0 ]];then trap - ERR EXIT;echo 1>&2;echo "*** fail *** : code $rc : $DIR/$SCRIPT $ARGS" 1>&2;echo 1>&2;exit $rc;fi' ERR EXIT
ARGS="$*"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$(basename "${BASH_SOURCE[0]}")"

# see /etc/sysctl.d/local.conf for setting of net.ipv4.ip_unprivileged_port_start
# and be sure to disable/stop any services that are using these ports (other than ssh/22)

tag=$1
shift

MIAC_DIR_HOST=$(cd ${DIR}/.. && pwd)

MIAC_HOSTNAME_GUEST=shed.cochleaudio.com

set -x
exec podman run \
     --replace \
     -it \
     --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add CAP_NET_RAW \
     -v ${MIAC_DIR_HOST}:/miac \
     --workdir /miac \
     --env PRIMARY_HOSTNAME=${MIAC_HOSTNAME_GUEST} \
     --env EMAIL_ADDR=me@cochleaudio.com \
     --env EMAIL_PW=12345678\
     --env SKIP_NETWORK_CHECKS=1 \
     --env DISABLE_FIREWALL=1 \
     --env NONINTERACTIVE=1 \
     --env MIAC_INSTALL= \
     --env MIAC_SYSTEMD= \
     -p 2222:22 \
     -p 25:25 \
     -p 53:53/udp \
     -p 53:53 \
     -p 80:80 \
     -p 443:443 \
     -p 465:465 \
     -p 587:587 \
     -p 993:993 \
     -p 995:995 \
     -p 4190:4190 \
     -h ${MIAC_HOSTNAME_GUEST} \
     --name miac-${tag} \
     miac-${tag} "$@"

#     --env MIAC_SYSTEMD= \
#     --env MIAC_HOSTNAME=$MIAC_HOSTNAME_GUEST \
#     --env MIAC_ADMIN_EMAIL=me@cochleaudio.com \
#     --env MIAC_ADMIN_PW=12345678 \
#     --env MIAC_TIMEZONE=Etc/UTC \

#      -v ${DIR}/user-data:/home/user-data \
#     --ip 10.0.2.100 \
#     --ip 10.0.2.63 \
#     --network=slirp4netns:cidr=10.2.21.0/24 \
#      --dns none \

# ufw limit 22/tcp
# ufw allow 25/tcp
# ufw allow 53
# ufw allow 80/tcp
# ufw allow 443/tcp
# ufw allow 465/tcp
# ufw allow 587/tcp
# ufw allow 993/tcp
# ufw allow 995/tcp
# ufw allow 4190/tcp
