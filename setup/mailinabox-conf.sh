
##### MIAC_GENERIC_BEGIN

# MIAC TODO: figure out env handling

cat > /etc/mailinabox.conf <<EOF
STORAGE_ROOT=$STORAGE_ROOT
STORAGE_USER=$STORAGE_USER
PUBLIC_IPV6=
PRIVATE_IPV6=
EOF

# Load the confguration
source /etc/mailinabox.conf

##### MIAC_GENERIC_END


##### MIAC_CONF_BEGIN

# MIAC TODO: figure out env handling

# Save the global options in /etc/mailinabox.conf so that standalone
# tools know where to look for data. The default MTA_STS_MODE setting
# is blank unless set by an environment variable, but see web.sh for
# how that is interpreted.
cat > /etc/mailinabox.conf << EOF
STORAGE_ROOT=$STORAGE_ROOT
STORAGE_USER=$STORAGE_USER
PUBLIC_IPV6=
#PUBLIC_IPV6=$PUBLIC_IPV6
PRIVATE_IPV6=
#PRIVATE_IPV6=$PRIVATE_IPV6

PRIMARY_HOSTNAME=$PRIMARY_HOSTNAME
PUBLIC_IP=$PUBLIC_IP
# podman rootless "ip"
PRIVATE_IP=10.0.2.100
#PRIVATE_IP=$PRIVATE_IP
MTA_STS_MODE=${DEFAULT_MTA_STS_MODE:-enforce}
EOF

# Load the confguration
source /etc/mailinabox.conf

##### MIAC_CONF_END


##### MIAC_SYSTEMD_BEGIN

# Load the confguration
source /etc/mailinabox.conf

##### MIAC_SYSTEMD_END
