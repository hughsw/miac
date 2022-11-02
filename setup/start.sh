#!/bin/bash
# This is the entry point for configuring the system.
#####################################################

# Check system setup: Are we running as root on Ubuntu 18.04 on a
# machine with enough memory? Is /tmp mounted with exec.
# If not, this shows an error and exits.
source setup/preflight.sh

source setup/functions.sh # load our functions
source setup/locale.sh # export locale env vars

# Migrate existing installation, capture DEFAULT_* config
source setup/migrate.sh

# Create /usr/local/bin/mailinabox
source setup/mailinabox-bin.sh

# Ask the user for the PRIMARY_HOSTNAME, PUBLIC_IP, and PUBLIC_IPV6,
# if values have not already been set in environment variables. When running
# non-interactively, be sure to set values for all! Also sets STORAGE_USER and
# STORAGE_ROOT.
source setup/questions.sh

# Run some network checks to make sure setup on this machine makes sense.
source setup/network-checks.sh

# Create the STORAGE_USER and STORAGE_ROOT directory if they don't already exist.
source setup/user-storage.sh

# Save the global options in /etc/mailinabox.conf
source setup/mailinabox-conf.sh


# Start service configuration.
source setup/system.sh
source setup/resolv.sh
source setup/fail2ban.sh
source setup/ssl.sh
source setup/dns.sh
source setup/mail-postfix.sh
source setup/mail-dovecot.sh
source setup/mail-users.sh
source setup/dkim.sh
source setup/spamassassin.sh
source setup/web.sh
source setup/webmail.sh
source setup/nextcloud.sh
source setup/zpush.sh
source setup/management.sh
source setup/munin.sh


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
restart_service fail2ban

# If there aren't any mail users yet, create one.
source setup/firstuser.sh

# Register with Let's Encrypt, including agreeing to the Terms of Service.
# We'd let certbot ask the user interactively, but when this script is
# run in the recommended curl-pipe-to-bash method there is no TTY and
# certbot will fail if it tries to ask.
if [ ! -d $STORAGE_ROOT/ssl/lets_encrypt/accounts/acme-v02.api.letsencrypt.org/ ]; then
echo
echo "-----------------------------------------------"
echo "Mail-in-a-Box uses Let's Encrypt to provision free SSL/TLS certificates"
echo "to enable HTTPS connections to your box. We're automatically"
echo "agreeing you to their subscriber agreement. See https://letsencrypt.org."
echo
certbot register --register-unsafely-without-email --agree-tos --config-dir $STORAGE_ROOT/ssl/lets_encrypt
fi

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
        	| sed "s/SHA256 Fingerprint=//i"
else
	echo https://$PUBLIC_IP/admin
	echo
	echo You will be alerted that the website has an invalid certificate. Check that
	echo the certificate fingerprint matches:
	echo
	openssl x509 -in $STORAGE_ROOT/ssl/ssl_certificate.pem -noout -fingerprint -sha256\
        	| sed "s/SHA256 Fingerprint=//i"
	echo
	echo Then you can confirm the security exception and continue.
	echo
fi
