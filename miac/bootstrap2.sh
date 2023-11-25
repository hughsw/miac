#!/bin/bash

# bootstrap a miac configuration

# podman container kill miac-flat
# podman container rm miac-flat
# podman run --rm -v /home/hugh/miac:/home/user-data miac-flat rm -r /home/user-data
# bootstrap2.sh flat


#set -u
set -uo pipefail

#set -x

function check_port {
    protocol=$1
    port=$2

    if [ $protocol = udp ] ; then maybe_udp=--udp ; else maybe_udp= ; fi

    # short timeout for quick success
    msg=$(timeout -k 0.5s 0.2s ncat -4 $maybe_udp --listen $port 2>&1)
    code=$?
    if [ $code = 124 ] ; then return 0 ; fi

    # try again, with a longer timeout
    msg=$(timeout -k 0.5s 0.5s ncat -4 $maybe_udp --listen $port 2>&1)
    code=$?
    if [ $code = 124 ] ; then return 0 ; fi

    echo $1 $port : $(echo $msg | sed -e 's/ncat://i' -e 's/quitting.//i')
    return 1
}
function check_ports {
    udp_ports="$1"
    tcp_ports="$2"

    local numfail=0

    for port in $udp_ports ; do
	check_port udp $port
	count=$?
	numfail=$(($numfail + $count))
    done

    for port in $tcp_ports ; do
	check_port tcp $port
	count=$?
	numfail=$(($numfail + $count))
    done

    if [ $numfail = 0 ] ; then return 0 ; fi

    echo "
There were port-binding failures: $numfail internet ports(s) could not be bound for servers to listen on.
Fix the permissions for low-number ports and/or stop the processes or services that have bound the port(s).

For permissions you may need to add file /etc/sysctl.d/local.conf with kernel parameter setting:
  net.ipv4.ip_unprivileged_port_start=53
and then load that kernel parameter setting with:
  $ sudo sysctl -p /etc/sysctl.d/local.conf

For processes or services, you must identify the processes or services which have bound the port(s), and
then permanently disable those processes or services.
"
    return $numfail
}

# Here we go

tag=$1
MIAC_SETUP_DIR=miac

echo "Checking podman"
if ! which podman > /dev/null ; then
    echo "
Failed podman:
The podman package does not seem to be installed.  Ensure an up-to-date version of podman is installed. E.g. on Debian/Ubuntu:
  $ sudo apt-get update
  $ sudo apt-get install podman
"
    exit 1
fi

expected_podman_version="podman version 3.0.1"
podman_version=$(podman --version 2>&1)
if [ "$podman_version" != "$expected_podman_version" ] ; then
    echo "
Failed podman:
Miac needs at least $expected_podman_version but found $podman_version
Ensure an up-to-date version of podman is installed. E.g. on Debian/Ubuntu:
  $ sudo apt-get update
  $ sudo apt-get install podman
"
    exit 1
fi
echo "Found $podman_version"

# Check that we can bind to ports
echo "Checking that we can bind internet ports"
udp_ports="20 53 10000 10 90"
tcp_ports="20 10000 80 10 90"
udp_ports=4000
tcp_ports=5000
check_ports "$udp_ports" "$tcp_ports"
numfail=$?
if [ $numfail != 0 ] ; then exit $numfail ; fi
echo "We can bind internet ports"


set -e
set -x

podman run --rm -p 8080:80 quay.io/podman/hello
#podman pull localhost/miac-$tag

miac_root=$HOME/miac
miac_timestamp=$miac_root/miac.timestamp
miac_env="miac-env.sh"
# storage_root is where miac_root is mounted in the container
storage_root=/home/user-data
MIAC_ENV=miac-env.sh

# Looks counterintuitive, but this rmdir attempt is a simple way to let the following
# block proceed if the directory currently exists and is empty
rmdir $miac_root 2> /dev/null || true

if [ ! -f $miac_timestamp -a -e $miac_root ] ; then
    echo "
Miac root directory failure:

The directory $miac_root must either hold a valid Miac installation, or not exist.
The directory (or file) $miac_root exists but does not look like a coherent Miac 
installation.  $miac_root must either be moved to a new name or deleted.

"
    exit 1
fi
if [ ! -e $miac_root ] ; then
    set -x
    mkdir -p $miac_root
    miac_root=$(cd $miac_root && pwd)

    #podman run --rm --env TERM=xterm-256color --env MIAC_ENV=$MIAC_ENV  -v $miac_root:${storage_root} miac-$tag $MIAC_SETUP_DIR/miac-conf.sh
    #
    ## get the password
    #source <(grep -e '\bEMAIL_PW=' $miac_root/$MIAC_ENV | sed -e 's/^export\s\+//')
    ## eliminate at rest password
    #sed -i -e 's/.*EMAIL_PW.*//' $miac_root/$MIAC_ENV

    #podman run  --rm miac-$tag pwd
    #podman run --rm  miac-$tag /bin/sh -c 'cd .. && pwd && ls -la . && df -h && ls -la /home'
    #podman run --rm  miac-$tag /bin/sh -x -c 'ls -la /home && rm ${storage_root} && mkdir ${storage_root} && ls -la /home'
    # copy the generic user-data into the host volume
    podman run --rm  -v $miac_root:${storage_root} miac-$tag rsync -a ../generic-user-data/ ${storage_root}
    # icanhazip.com  https://ipv4.icanhazip.com/   https://ipv6.icanhazip.com/
    public_ip=$(curl -sS -4 --fail --silent --max-time 15 ipv4.icanhazip.com 2>/dev/null || /bin/true)
    echo public_ip: $public_ip
    # not working...
    #admin_pw=$(podman run -it --rm --env TERM=screen.xterm-256color -v $miac_root:${storage_root} miac-$tag $MIAC_SETUP_DIR/miac-conf.py $public_ip ${storage_root}/${miac_env} 3>&2 2>&1 1>&3)
    #podman run -it --rm  -v $miac_root:${storage_root} -v ${HOME}/work/miac:/miac miac-$tag /bin/bash -c 'sudo bash -x $MIAC_SETUP_DIR/miac-setup-conf.sh 2>&1 | tee --output-error=exit /miac/logs/miac-setup-conf.log_$(date "+%Y-%m-%d-%H%M-%S") '

    # This runs interactive dialog for basic config, and then miac-setup-ssl.sh to generate secrets, all stored into miac_root
    podman run -it --rm --env TERM=screen.xterm-256color -v $miac_root:${storage_root} miac-$tag $MIAC_SETUP_DIR/miac-conf.sh $public_ip ${storage_root}/${miac_env}

    # NOTE DEV ONLY -- important conditions to think about vis-a-vis migrations
    # Copy backup-related secrets so as to preserve backup integrity across image rebuilds and the ssl generation above
    cp -av secrets/* $miac_root/backup/
    #cp -av secrets/ $miac_root/backup
    #rsync -av secrets/ $miac_root/backup

    #podman run -it --rm --env TERM=screen.xterm-256color -v $miac_root:${storage_root} miac-$tag $MIAC_SETUP_DIR/miac-conf.py $public_ip ${storage_root}/${miac_env}
    date -Iminutes > $miac_timestamp
fi

set -x

# non export version
sed -e 's/^export\s\+//' ${miac_root}/${miac_env} > ${miac_root}/miac-env-nox.sh

# Get PRIMARY_HOSTNAME
source <(grep -e '\bPRIMARY_HOSTNAME=' $miac_root/miac-env-nox.sh)

cid=$(podman run \
     --detach \
     --restart=always \
     --interactive  --tty \
     --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add CAP_NET_RAW \
     -v ${miac_root}:${storage_root} \
     -v ${HOME}/work/miac:/miac \
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
     -h $PRIMARY_HOSTNAME \
     --name miac-${tag} \
     miac-${tag})


#podman exec -it --env-file ${miac_root}/miac-env-nox.sh $cid /bin/bash -c 'fgrep $PRIMARY_HOSTNAME /etc/hosts || (echo && echo "127.0.0.1       $PRIMARY_HOSTNAME") >> /etc/hosts'

podman exec -it --env-file ${miac_root}/miac-env-nox.sh -u miac:miac $cid $MIAC_SETUP_DIR/miac

exec podman exec -it --detach-keys="" --env-file ${miac_root}/miac-env-nox.sh -u miac:miac $cid /bin/bash --login

#     -v ${miac_root}:/home/hugh-miac \
