# MIAC: SYSTEMD

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# mailinabox-conf.sh
#
echo MIAC SYSTEMD mailinabox-conf.sh

# Load the confguration
source /etc/mailinabox.conf



######################################################################
#
# dns.sh
#
echo MIAC SYSTEMD dns.sh

# MIAC TODO: cron config and activation...

# Force the dns_update script to be run every day to re-sign zones for DNSSEC
# before they expire. When we sign zones (in `dns_update.py`) we specify a
# 30-day validation window, so we had better re-sign before then.
cat > /etc/cron.daily/mailinabox-dnssec << EOF;
#!/bin/bash
# Mail-in-a-Box
# Re-sign any DNS zones with DNSSEC because the signatures expire periodically.
$(pwd)/tools/dns_update
EOF
chmod +x /etc/cron.daily/mailinabox-dnssec



######################################################################
#
# mail-postfix.sh
#
echo MIAC SYSTEMD mail-postfix.sh

/etc/cron.daily/mailinabox-postgrey-whitelist


# Restart services

restart_service postfix
restart_service postgrey



######################################################################
#
# mail-dovecot.sh
#
echo MIAC SYSTEMD mail-dovecot.sh

# Restart services.
restart_service dovecot



######################################################################
#
# mail-users.sh
#
echo MIAC SYSTEMD mail-users.sh

# Restart Services
##################

restart_service postfix
restart_service dovecot



######################################################################
#
# dkim.sh
#
echo MIAC SYSTEMD dkim.sh

# We need to explicitly enable the opendmarc service, or it will not start
hide_output systemctl enable opendmarc

# Restart services.
restart_service opendkim
restart_service opendmarc
restart_service postfix



######################################################################
#
# spamassassin.sh
#
echo MIAC SYSTEMD spamassassin.sh

# Initial training?
# sa-learn --ham storage/mail/mailboxes/*/*/cur/
# sa-learn --spam storage/mail/mailboxes/*/*/.Spam/cur/

# Kick services.
restart_service spampd
restart_service dovecot



######################################################################
#
# web.sh
#
echo MIAC SYSTEMD web.sh

# Start services.
restart_service nginx
restart_service php$PHP_VER-fpm



######################################################################
#
# webmail.sh
#
echo MIAC SYSTEMD webmail.sh

# Enable PHP modules.
phpenmod -v $PHP_VER imap
restart_service php$PHP_VER-fpm



######################################################################
#
# nextcloud.sh
#
echo MIAC SYSTEMD nextcloud.sh

# Set up a cron job for Nextcloud.
cat > /etc/cron.d/mailinabox-nextcloud << EOF;
#!/bin/bash
# Mail-in-a-Box
*/5 * * * *	root	sudo -u www-data php$PHP_VER -f /usr/local/lib/owncloud/cron.php
EOF
chmod +x /etc/cron.d/mailinabox-nextcloud

# There's nothing much of interest that a user could do as an admin for Nextcloud,
# and there's a lot they could mess up, so we don't make any users admins of Nextcloud.
# But if we wanted to, we would do this:
# ```
# for user in $(management/cli.py user admins); do
#	 sqlite3 $STORAGE_ROOT/owncloud/owncloud.db "INSERT OR IGNORE INTO oc_group_user VALUES ('admin', '$user')"
# done
# ```

# Enable PHP modules and restart PHP.
restart_service php$PHP_VER-fpm



######################################################################
#
# zpush.sh
#
echo MIAC SYSTEMD zpush.sh

# Restart service.

restart_service php$PHP_VER-fpm

# Fix states after upgrade

hide_output php$PHP_VER /usr/local/lib/z-push/z-push-admin.php -a fixstates



######################################################################
#
# management.sh
#
echo MIAC SYSTEMD management.sh

hide_output systemctl link -f /lib/systemd/system/mailinabox.service
daemon_reload_systemctl
hide_output systemctl enable mailinabox.service


# Start the management server.
restart_service mailinabox



######################################################################
#
# munin.sh
#
echo MIAC SYSTEMD munin.sh

hide_output systemctl link -f /lib/systemd/system/munin.service
daemon_reload_systemctl
hide_output systemctl unmask munin.service
hide_output systemctl enable munin.service

# Restart services.
restart_service munin
restart_service munin-node

# generate initial statistics so the directory isn't empty
# (We get "Pango-WARNING **: error opening config file '/root/.config/pango/pangorc': Permission denied"
# if we don't explicitly set the HOME directory when sudo'ing.)
# We check to see if munin-cron is already running, if it is, there is no need to run it simultaneously
# generating an error.
if [ ! -f /var/run/munin/munin-update.lock ]; then
    # MIAC abstract this kind of activity...
    sudo -H -u munin munin-cron
fi



######################################################################
#
# update-state.sh
#
echo MIAC SYSTEMD update-state.sh

# Wait for the management daemon to start...
until nc -z -w 4 127.0.0.1 10222
do
    # MIAC include a failure timeout
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



######################################################################
#
# firstuser.sh
#
echo MIAC SYSTEMD firstuser.sh

# If there aren't any mail users yet, create one.
if [ -z "$(management/cli.py user)" ]; then
	# The outut of "management/cli.py user" is a list of mail users. If there
	# aren't any yet, it'll be empty.

	# If we didn't ask for an email address at the start, do so now.
	if [ -z "${EMAIL_ADDR:-}" ]; then
		# In an interactive shell, ask the user for an email address.
		if [ -z "${NONINTERACTIVE:-}" ]; then
			input_box "Mail Account" \
				"Let's create your first mail account.
				\n\nWhat email address do you want?" \
				me@$(get_default_hostname) \
				EMAIL_ADDR

			if [ -z "$EMAIL_ADDR" ]; then
				# user hit ESC/cancel
				exit
			fi
			while ! management/mailconfig.py validate-email "$EMAIL_ADDR"
			do
				input_box "Mail Account" \
					"That's not a valid email address.
					\n\nWhat email address do you want?" \
					$EMAIL_ADDR \
					EMAIL_ADDR
				if [ -z "$EMAIL_ADDR" ]; then
					# user hit ESC/cancel
					exit
				fi
			done

		# But in a non-interactive shell, just make something up.
		# This is normally for testing.
		else
			# Use me@PRIMARY_HOSTNAME
			EMAIL_ADDR=me@$PRIMARY_HOSTNAME
			EMAIL_PW=12345678
			echo
			echo "Creating a new administrative mail account for $EMAIL_ADDR with password $EMAIL_PW."
			echo
		fi
	else
		echo
		echo "Okay. I'm about to set up $EMAIL_ADDR for you. This account will also"
		echo "have access to the box's control panel."
	fi

	# Create the user's mail account. This will ask for a password if none was given above.
	management/cli.py user add $EMAIL_ADDR ${EMAIL_PW:-}

	# Make it an admin.
	hide_output management/cli.py user make-admin $EMAIL_ADDR

	# Create an alias to which we'll direct all automatically-created administrative aliases.
	management/cli.py alias add administrator@$PRIMARY_HOSTNAME $EMAIL_ADDR > /dev/null
fi

# MIAC This nsd churn has been necessary at times -- something is clearly fragile,
# given recent changes (hacks) to work around failures of:
#    $ nsd-control reconfig
#    $ nsd-control reload
restart_service nsd
nsd-control reconfig
nsd-control reload
restart_service nsd



######################################################################
#
# running-banner.sh
#
echo MIAC SYSTEMD running-banner.sh

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


# ensure success code when this script is sourced
/bin/true

