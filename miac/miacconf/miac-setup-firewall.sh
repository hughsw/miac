# MIAC: FIREWALL

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# system.sh
#
echo MIAC FIREWALL system.sh

# ### Firewall

# Various virtualized environments like Docker and some VPSs don't provide #NODOC
# a kernel that supports iptables. To avoid error-like output in these cases, #NODOC
# we skip this if the user sets DISABLE_FIREWALL=1. #NODOC
if [ -z "${DISABLE_FIREWALL:-}" ]; then
	# Install `ufw` which provides a simple firewall configuration.
	apt_install ufw

	# Allow incoming connections to SSH.
	ufw_limit ssh;

	# ssh might be running on an alternate port. Use sshd -T to dump sshd's #NODOC
	# settings, find the port it is supposedly running on, and open that port #NODOC
	# too. #NODOC
	SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | sed "s/port //") #NODOC
	if [ ! -z "$SSH_PORT" ]; then
	if [ "$SSH_PORT" != "22" ]; then

	echo Opening alternate SSH port $SSH_PORT. #NODOC
	ufw_limit $SSH_PORT #NODOC

	fi
	fi

	ufw --force enable;
fi #NODOC



######################################################################
#
# dns.sh
#
echo MIAC FIREWALL dns.sh

# Permit DNS queries on TCP/UDP in the firewall.

ufw_allow domain



######################################################################
#
# mail-postfix.sh
#
echo MIAC FIREWALL mail-postfix.sh

# Allow the two SMTP ports in the firewall.

ufw_allow smtp
ufw_allow smtps
ufw_allow submission



######################################################################
#
# mail-dovecot.sh
#
echo MIAC FIREWALL mail-dovecot.sh

# Allow the IMAP/POP ports in the firewall.
ufw_allow imaps
ufw_allow pop3s

# Allow the Sieve port in the firewall.
ufw_allow sieve



######################################################################
#
# web.sh
#
echo MIAC FIREWALL web.sh

# Open ports.
ufw_allow http
ufw_allow https


# ensure success code when this script is sourced
/bin/true

