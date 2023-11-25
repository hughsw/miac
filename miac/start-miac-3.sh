#!/bin/bash

# Note: Asumes systemd is running

# Set strict, Load functions
source setup/functions.sh 
# Export some locale envs
source setup/locale.sh

# Load global vars
source /etc/mailinabox.conf 

# continue

# From setup/system.sh
# First we'll disable systemd-resolved's management of resolv.conf and its stub server.
# Breaking the symlink to /run/systemd/resolve/stub-resolv.conf means
# systemd-resolved will read it for DNS servers to use. Put in 127.0.0.1,
# which is where bind9 will be running. Obviously don't do this before
# installing bind9 or else apt won't be able to resolve a server to
# download bind9 from.
echo > /etc/resolv.conf
tools/editconf.py /etc/systemd/resolved.conf DNSStubListener=no
echo "nameserver 127.0.0.1" > /etc/resolv.conf

service bind9 restart
systemctl restart systemd-resolved

# Do this late
source setup/dns.sh
touch /var/log/nsd.log
chown nsd:nsd  /var/log/nsd.log

service nsd restart
#service munin restart
#service munin-node restart

service dovecot restart
service fail2ban restart
service mailinabox restart
service munin-node restart
service munin restart
service nginx restart
service opendkim restart
service opendmarc restart
service php8.0-fpm restart
service postfix restart
service postgrey restart
service spampd restart

if [ -z "${DISABLE_FIREWALL:-}" ]; then
    ufw --force reset
    ufw allow domain
    ufw allow imaps
    ufw allow pop3s
    ufw allow sieve
    ufw allow smtp
    ufw allow smtps
    ufw allow submission
    ufw_limit ssh;
    #system.sh:277:	ufw_limit $SSH_PORT #NODOC
    ufw allow http
    ufw allow https
    ufw --force enable;
fi

#systemctl reload-daemon

systemctl daemon-reload

# Wait for the management daemon to start...
until nc -z -w 4 127.0.0.1 10222
do
    echo Waiting for the Mail-in-a-Box management daemon to start...
    sleep 2
done

# ...and then have it write the DNS and nginx configuration files and start those
# services.
tools/dns_update
tools/web_update

# Give fail2ban another restart. The log files may not all have been present when
# fail2ban was first configured, but they should exist now.
#service fail2ban restart

# If there aren't any mail users yet, create one.
source setup/firstuser.sh

service nsd restart


# Done.
echo
echo "-----------------------------------------------"
echo
echo Your Mail-in-a-Box is running.
echo
echo Please log in to the control panel for further instructions at:
echo
if management/status_checks.py --check-primary-hostname; then
    # Show the nice URL if it appears to be resolving and has a valid certificate.
    echo https://$PRIMARY_HOSTNAME/admin
    echo
    echo "If you have a DNS problem put the box's IP address in the URL"
    echo "(https://$PUBLIC_IP/admin) but then check the TLS fingerprint:"
    openssl x509 -in $STORAGE_ROOT/ssl/ssl_certificate.pem -noout -fingerprint -sha256\
        | sed "s/SHA256 Fingerprint=//"
else
    echo https://$PUBLIC_IP/admin
    echo
    echo You will be alerted that the website has an invalid certificate. Check that
    echo the certificate fingerprint matches:
    echo
    openssl x509 -in $STORAGE_ROOT/ssl/ssl_certificate.pem -noout -fingerprint -sha256\
        | sed "s/SHA256 Fingerprint=//"
    echo
    echo Then you can confirm the security exception and continue.
    echo
fi

true
