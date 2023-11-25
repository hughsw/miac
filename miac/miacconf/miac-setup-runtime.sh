# MIAC: RUNTIME

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# resolv.sh
#
echo MIAC RUNTIME resolv.sh

# MIAC abstract this

# First we'll disable systemd-resolved's management of resolv.conf and its stub server.
# Breaking the symlink to /run/systemd/resolve/stub-resolv.conf means
# systemd-resolved will read it for DNS servers to use. Put in 127.0.0.1,
# which is where bind9 will be running. Obviously don't do this before
# installing bind9 or else apt won't be able to resolve a server to
# download bind9 from.
# Overwrite resolv.conf because some VMs bind-mount it, making it unremoveable.
echo > /etc/resolv.conf
tools/editconf.py /etc/systemd/resolved.conf DNSStubListener=no
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# Restart the DNS services.

restart_service bind9
restart_systemctl systemd-resolved



######################################################################
#
# fail2ban.sh
#
echo MIAC RUNTIME fail2ban.sh

# On first installation, the log files that the jails look at don't all exist.
# e.g., The roundcube error log isn't normally created until someone logs into
# Roundcube for the first time. This causes fail2ban to fail to start. Later
# scripts will ensure the files exist and then fail2ban is given another
# restart at the very end of setup.
restart_service fail2ban


# ensure success code when this script is sourced
/bin/true

