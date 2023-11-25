
# MUST coordinate with miac-generic.df
# TODO: figure out how to use systemd to get these env vars into sshd/login environment
export STORAGE_ROOT=/home/user-data
export STORAGE_USER=user-data
export PRIMARY_HOSTNAME=shed.cochleaudio.com
export EMAIL_ADDR=me@cochleaudio.com
export EMAIL_PW=12345678

# Setting these prevents certain default actions
export NONINTERACTIVE=1
export SKIP_NETWORK_CHECKS=1
export DISABLE_FIREWALL=1

export MIAC_INSTALL=1
export MIAC_SYSTEMD=
export MIAC_CONF=
