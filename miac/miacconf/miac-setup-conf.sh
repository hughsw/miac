# MIAC: CONF

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# questions.sh
#
echo MIAC CONF questions.sh

if [ -z "${NONINTERACTIVE:-}" ]; then

	
	message_box "Mail-in-a-Box Installation" \
		"Hello and thanks for deploying a Mail-in-a-Box!
		\n\nI'm going to ask you a few questions.
		\n\nTo change your answers later, just run 'sudo mailinabox' from the command line.
		\n\nNOTE: You should only install this on a brand new Ubuntu installation 100% dedicated to Mail-in-a-Box. Mail-in-a-Box will, for example, remove apache2."
fi

# The box needs a name.
if [ -z "${PRIMARY_HOSTNAME:-}" ]; then
	if [ -z "${DEFAULT_PRIMARY_HOSTNAME:-}" ]; then
		# We recommend to use box.example.com as this hosts name. The
		# domain the user possibly wants to use is example.com then.
		# We strip the string "box." from the hostname to get the mail
		# domain. If the hostname differs, nothing happens here.
		DEFAULT_DOMAIN_GUESS=$(echo $(get_default_hostname) | sed -e 's/^box\.//')

		# This is the first run. Ask the user for his email address so we can
		# provide the best default for the box's hostname.
		input_box "Your Email Address" \
"What email address are you setting this box up to manage?
\n\nThe part after the @-sign must be a domain name or subdomain
that you control. You can add other email addresses to this
box later (including email addresses on other domain names
or subdomains you control).
\n\nWe've guessed an email address. Backspace it and type in what
you really want.
\n\nEmail Address:" \
			"me@$DEFAULT_DOMAIN_GUESS" \
			EMAIL_ADDR

		if [ -z "$EMAIL_ADDR" ]; then
			# user hit ESC/cancel
			exit
		fi
		while ! python3 management/mailconfig.py validate-email "$EMAIL_ADDR"
		do
			input_box "Your Email Address" \
				"That's not a valid email address.\n\nWhat email address are you setting this box up to manage?" \
				$EMAIL_ADDR \
				EMAIL_ADDR
			if [ -z "$EMAIL_ADDR" ]; then
				# user hit ESC/cancel
				exit
			fi
		done

		# Take the part after the @-sign as the user's domain name, and add
		# 'box.' to the beginning to create a default hostname for this machine.
		DEFAULT_PRIMARY_HOSTNAME=box.$(echo $EMAIL_ADDR | sed 's/.*@//')
	fi

	input_box "Hostname" \
"This box needs a name, called a 'hostname'. The name will form a part of the box's web address.
\n\nWe recommend that the name be a subdomain of the domain in your email
address, so we're suggesting $DEFAULT_PRIMARY_HOSTNAME.
\n\nYou can change it, but we recommend you don't.
\n\nHostname:" \
		$DEFAULT_PRIMARY_HOSTNAME \
		PRIMARY_HOSTNAME

	if [ -z "$PRIMARY_HOSTNAME" ]; then
		# user hit ESC/cancel
		exit
	fi
fi

# If the machine is behind a NAT, inside a VM, etc., it may not know
# its IP address on the public network / the Internet. Ask the Internet
# and possibly confirm with user.
if [ -z "${PUBLIC_IP:-}" ]; then
	# Ask the Internet.
	GUESSED_IP=$(get_publicip_from_web_service 4)

	# On the first run, if we got an answer from the Internet then don't
	# ask the user.
	if [[ -z "${DEFAULT_PUBLIC_IP:-}" && ! -z "$GUESSED_IP" ]]; then
		PUBLIC_IP=$GUESSED_IP

	# Otherwise on the first run at least provide a default.
	elif [[ -z "${DEFAULT_PUBLIC_IP:-}" ]]; then
		DEFAULT_PUBLIC_IP=$(get_default_privateip 4)

	# On later runs, if the previous value matches the guessed value then
	# don't ask the user either.
	elif [ "${DEFAULT_PUBLIC_IP:-}" == "$GUESSED_IP" ]; then
		PUBLIC_IP=$GUESSED_IP
	fi

	if [ -z "${PUBLIC_IP:-}" ]; then
		input_box "Public IP Address" \
			"Enter the public IP address of this machine, as given to you by your ISP.
			\n\nPublic IP address:" \
			${DEFAULT_PUBLIC_IP:-} \
			PUBLIC_IP

		if [ -z "$PUBLIC_IP" ]; then
			# user hit ESC/cancel
			exit
		fi
	fi
fi

# Same for IPv6. But it's optional. Also, if it looks like the system
# doesn't have an IPv6, don't ask for one.
if [ -z "${PUBLIC_IPV6:-}" ]; then
	# Ask the Internet.
	GUESSED_IP=$(get_publicip_from_web_service 6)
	MATCHED=0
	if [[ -z "${DEFAULT_PUBLIC_IPV6:-}" && ! -z "$GUESSED_IP" ]]; then
		PUBLIC_IPV6=$GUESSED_IP
	elif [[ "${DEFAULT_PUBLIC_IPV6:-}" == "$GUESSED_IP" ]]; then
		# No IPv6 entered and machine seems to have none, or what
		# the user entered matches what the Internet tells us.
		PUBLIC_IPV6=$GUESSED_IP
		MATCHED=1
	elif [[ -z "${DEFAULT_PUBLIC_IPV6:-}" ]]; then
		DEFAULT_PUBLIC_IP=$(get_default_privateip 6)
	fi

	if [[ -z "${PUBLIC_IPV6:-}" && $MATCHED == 0 ]]; then
		input_box "IPv6 Address (Optional)" \
			"Enter the public IPv6 address of this machine, as given to you by your ISP.
			\n\nLeave blank if the machine does not have an IPv6 address.
			\n\nPublic IPv6 address:" \
			${DEFAULT_PUBLIC_IPV6:-} \
			PUBLIC_IPV6

		if [ ! $PUBLIC_IPV6_EXITCODE ]; then
			# user hit ESC/cancel
			exit
		fi
	fi
fi

# Get the IP addresses of the local network interface(s) that are connected
# to the Internet. We need these when we want to have services bind only to
# the public network interfaces (not loopback, not tunnel interfaces).
if [ -z "${PRIVATE_IP:-}" ]; then
	PRIVATE_IP=$(get_default_privateip 4)
fi
if [ -z "${PRIVATE_IPV6:-}" ]; then
	PRIVATE_IPV6=$(get_default_privateip 6)
fi
if [[ -z "$PRIVATE_IP" && -z "$PRIVATE_IPV6" ]]; then
	echo
	echo "I could not determine the IP or IPv6 address of the network inteface"
	echo "for connecting to the Internet. Setup must stop."
	echo
	hostname -I
	route
	echo
	exit
fi

# Automatic configuration, e.g. as used in our Vagrant configuration.
if [ "$PUBLIC_IP" = "auto" ]; then
	# Use a public API to get our public IP address, or fall back to local network configuration.
	PUBLIC_IP=$(get_publicip_from_web_service 4 || get_default_privateip 4)
fi
if [ "$PUBLIC_IPV6" = "auto" ]; then
	# Use a public API to get our public IPv6 address, or fall back to local network configuration.
	PUBLIC_IPV6=$(get_publicip_from_web_service 6 || get_default_privateip 6)
fi
if [ "$PRIMARY_HOSTNAME" = "auto" ]; then
	PRIMARY_HOSTNAME=$(get_default_hostname)
fi

# Set STORAGE_USER and STORAGE_ROOT to default values (user-data and /home/user-data), unless
# we've already got those values from a previous run.
if [ -z "${STORAGE_USER:-}" ]; then
	STORAGE_USER=$([[ -z "${DEFAULT_STORAGE_USER:-}" ]] && echo "user-data" || echo "$DEFAULT_STORAGE_USER")
fi
if [ -z "${STORAGE_ROOT:-}" ]; then
	STORAGE_ROOT=$([[ -z "${DEFAULT_STORAGE_ROOT:-}" ]] && echo "/home/$STORAGE_USER" || echo "$DEFAULT_STORAGE_ROOT")
fi

# Show the configuration, since the user may have not entered it manually.
echo
echo "Primary Hostname: $PRIMARY_HOSTNAME"
echo "Public IP Address: $PUBLIC_IP"
if [ ! -z "$PUBLIC_IPV6" ]; then
	echo "Public IPv6 Address: $PUBLIC_IPV6"
fi
if [ "$PRIVATE_IP" != "$PUBLIC_IP" ]; then
	echo "Private IP Address: $PRIVATE_IP"
fi
if [ "$PRIVATE_IPV6" != "$PUBLIC_IPV6" ]; then
	echo "Private IPv6 Address: $PRIVATE_IPV6"
fi
if [ -f /usr/bin/git ] && [ -d .git ]; then
	echo "Mail-in-a-Box Version: " $(git describe 2> /dev/null || echo Unknown)
fi
echo



######################################################################
#
# network-checks.sh
#
echo MIAC CONF network-checks.sh

# Run some network checks to make sure setup on this machine makes sense.
# Skip on existing installs since we don't want this to block the ability to
# upgrade, and these checks are also in the control panel status checks.
if [ -z "${DEFAULT_PRIMARY_HOSTNAME:-}" -a -z "${SKIP_NETWORK_CHECKS:-}" ]; then

    # Install the 'host', 'sed', and and 'nc' tools. This script is run before
    # the rest of the system setup so we may not yet have things installed.
    apt_get_quiet install bind9-host sed netcat-openbsd

    # Stop if the PRIMARY_HOSTNAME is listed in the Spamhaus Domain Block List.
    # The user might have chosen a name that was previously in use by a spammer
    # and will not be able to reliably send mail. Do this after any automatic
    # choices made above.
    if host $PRIMARY_HOSTNAME.dbl.spamhaus.org > /dev/null; then
	echo
	echo "The hostname you chose '$PRIMARY_HOSTNAME' is listed in the"
	echo "Spamhaus Domain Block List. See http://www.spamhaus.org/dbl/"
	echo "and http://www.spamhaus.org/query/domain/$PRIMARY_HOSTNAME."
	echo
	echo "You will not be able to send mail using this domain name, so"
	echo "setup cannot continue."
	echo
	exit 1
    fi

    # Stop if the IPv4 address is listed in the ZEN Spamhouse Block List.
    # The user might have ended up on an IP address that was previously in use
    # by a spammer, or the user may be deploying on a residential network. We
    # will not be able to reliably send mail in these cases.
    REVERSED_IPV4=$(echo $PUBLIC_IP | sed "s/\([0-9]*\).\([0-9]*\).\([0-9]*\).\([0-9]*\)/\4.\3.\2.\1/")
    if host $REVERSED_IPV4.zen.spamhaus.org > /dev/null; then
	echo
	echo "The IP address $PUBLIC_IP is listed in the Spamhaus Block List."
	echo "See http://www.spamhaus.org/query/ip/$PUBLIC_IP."
	echo
	echo "You will not be able to send mail using this machine, so setup"
	echo "cannot continue."
	echo
	echo "Associate a different IP address with this machine if possible."
	echo "Many residential network IP addresses are listed, so Mail-in-a-Box"
	echo "typically cannot be used on a residential Internet connection."
	echo
	exit 1
    fi

    # Stop if we cannot make an outbound connection on port 25. Many residential
    # networks block outbound port 25 to prevent their network from sending spam.
    # See if we can reach one of Google's MTAs with a 5-second timeout.
    if ! nc -z -w5 aspmx.l.google.com 25; then
	echo
	echo "Outbound mail (port 25) seems to be blocked by your network."
	echo
	echo "You will not be able to send mail using this machine, so setup"
	echo "cannot continue."
	echo
	echo "Many residential networks block port 25 to prevent hijacked"
	echo "machines from being able to send spam. I just tried to connect"
	echo "to Google's mail server on port 25 but the connection did not"
	echo "succeed."
	echo
	exit 1
    fi

fi

true


######################################################################
#
# mailinabox-conf.sh
#
echo MIAC CONF mailinabox-conf.sh

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



######################################################################
#
# system.sh
#
echo MIAC CONF system.sh

# Basic System Configuration
# -------------------------

# ### Set hostname of the box

# If the hostname is not correctly resolvable sudo can't be used. This will result in
# errors during the install.
#

# Conditionalized because some VMs forbid changing the hostname -- for these,
# PRIMARY_HOSTNAME must be set correctly and this code is updating /etc/hostname
if [[ "$PRIMARY_HOSTNAME" != "$(< /etc/hostname)" ]]; then
    # set the hostname in the configuration file, then activate the setting
    echo $PRIMARY_HOSTNAME > /etc/hostname
    hostname $PRIMARY_HOSTNAME
fi


# ### Set the system timezone
#
# Some systems are missing /etc/timezone, which we cat into the configs for
# Z-Push and ownCloud, so we need to set it to something. Daily cron tasks
# like the system backup are run at a time tied to the system timezone, so
# letting the user choose will help us identify the right time to do those
# things (i.e. late at night in whatever timezone the user actually lives
# in).
#
# However, changing the timezone once it is set seems to confuse fail2ban
# and requires restarting fail2ban (done below in the fail2ban
# section) and syslog (see #328). There might be other issues, and it's
# not likely the user will want to change this, so we only ask on first
# setup.
if [ -z "${NONINTERACTIVE:-}" ]; then
	if [ ! -f /etc/timezone ] || [ ! -z ${FIRST_TIME_SETUP:-} ]; then
		# If the file is missing or this is the user's first time running
		# Mail-in-a-Box setup, run the interactive timezone configuration
		# tool.
		dpkg-reconfigure tzdata
		restart_service rsyslog
	fi
else
        # MIAC TODO: use MIAC_TIMEZONE

	# This is a non-interactive setup so we can't ask the user.
	# If /etc/timezone is missing, set it to UTC.
	if [ ! -f /etc/timezone ]; then
		echo "Setting timezone to UTC."
		echo "Etc/UTC" > /etc/timezone
		restart_service rsyslog
	fi
fi



######################################################################
#
# fail2ban.sh
#
echo MIAC CONF fail2ban.sh

# ### Fail2Ban Service

# Configure the Fail2Ban installation to prevent dumb bruce-force attacks against dovecot, postfix, ssh, etc.
rm -f /etc/fail2ban/jail.local # we used to use this file but don't anymore
rm -f /etc/fail2ban/jail.d/defaults-debian.conf # removes default config so we can manage all of fail2ban rules in one config

    cat conf/fail2ban/jails.conf \
	| sed "s/PUBLIC_IPV6/$PUBLIC_IPV6/g" \
	| sed "s/PUBLIC_IP/$PUBLIC_IP/g" \
	| sed "s#STORAGE_ROOT#$STORAGE_ROOT#" \
	      > /etc/fail2ban/jail.d/mailinabox.conf



######################################################################
#
# dns.sh
#
echo MIAC CONF dns.sh

#!/bin/bash
# DNS
# -----------------------------------------------

# This script installs packages, but the DNS zone files are only
# created by the /dns/update API in the management server because
# the set of zones (domains) hosted by the server depends on the
# mail users & aliases created by the user later.


cat > /etc/nsd/nsd.conf << EOF;
# Do not edit. Overwritten by Mail-in-a-Box setup.
server:
  hide-version: yes
  logfile: "/var/log/nsd.log"

  # identify the server (CH TXT ID.SERVER entry).
  identity: ""

  # The directory for zonefile: files.
  zonesdir: "/etc/nsd/zones"

  # Allows NSD to bind to IP addresses that are not (yet) added to the
  # network interface. This allows nsd to start even if the network stack
  # isn't fully ready, which apparently happens in some cases.
  # See https://www.nlnetlabs.nl/projects/nsd/nsd.conf.5.html.
  ip-transparent: yes

EOF

# MIAC TODO: set PRIVATE_IP, unset PRIVATE_IPV6

# Since we have bind9 listening on localhost for locally-generated
# DNS queries that require a recursive nameserver, and the system
# might have other network interfaces for e.g. tunnelling, we have
# to be specific about the network interfaces that nsd binds to.
for ip in $PRIVATE_IP $PRIVATE_IPV6; do
    echo "  ip-address: $ip" >> /etc/nsd/nsd.conf;
done

# Create a directory for additional configuration directives, including
# the zones.conf file written out by our management daemon.
echo "include: /etc/nsd/nsd.conf.d/*.conf" >> /etc/nsd/nsd.conf;



######################################################################
#
# mail-postfix.sh
#
echo MIAC CONF mail-postfix.sh

#!/bin/bash
#
# Postfix (SMTP)
# --------------
#
# Postfix handles the transmission of email between servers
# using the SMTP protocol. It is a Mail Transfer Agent (MTA).
#
# Postfix listens on port 25 (SMTP) for incoming mail from
# other servers on the Internet. It is responsible for very
# basic email filtering such as by IP address and greylisting,
# it checks that the destination address is valid, rewrites
# destinations according to aliases, and passses email on to
# another service for local mail delivery.
#
# The first hop in local mail delivery is to spampd via
# LMTP. spampd then passes mail over to Dovecot for
# storage in the user's mailbox.
#
# Postfix also listens on ports 465/587 (SMTPS, SMTP+STARTLS) for
# connections from users who can authenticate and then sends
# their email out to the outside world. Postfix queries Dovecot
# to authenticate users.
#
# Address validation, alias rewriting, and user authentication
# is configured in a separate setup script mail-users.sh
# because of the overlap of this part with the Dovecot
# configuration.


# ### Basic Settings

# Set some basic settings...
#
# * Have postfix listen on all network interfaces.
# * Make outgoing connections on a particular interface (if multihomed) so that SPF passes on the receiving side.
# * Set our name (the Debian default seems to be "localhost" but make it our hostname).
# * Set the name of the local machine to localhost, which means xxx@localhost is delivered locally, although we don't use it.

# * Set the SMTP banner (which must have the hostname first, then anything).
tools/editconf.py /etc/postfix/main.cf \
		      inet_interfaces=all \
		      smtp_bind_address=$PRIVATE_IP \
		      smtp_bind_address6=$PRIVATE_IPV6 \
		      myhostname=$PRIMARY_HOSTNAME\
		      smtpd_banner="\$myhostname ESMTP Hi, I'm a Mail-in-a-Box (Ubuntu/Postfix; see https://mailinabox.email/)" \
		      mydestination=localhost


# Configuring a specific installation, not just a generic build

# Modify the `outgoing_mail_header_filters` file to use the local machine name and ip
# on the first received header line.  This may help reduce the spam score of email by
# removing the 127.0.0.1 reference.
sed -i "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" /etc/postfix/outgoing_mail_header_filters
sed -i "s/PUBLIC_IP/$PUBLIC_IP/" /etc/postfix/outgoing_mail_header_filters



######################################################################
#
# mail-dovecot.sh
#
echo MIAC CONF mail-dovecot.sh

#!/bin/bash
#
# Dovecot (IMAP/POP and LDA)
# ----------------------
#
# Dovecot is *both* the IMAP/POP server (the protocol that email applications
# use to query a mailbox) as well as the local delivery agent (LDA),
# meaning it is responsible for writing emails to mailbox storage on disk.
# You could imagine why these things would be bundled together.
#
# As part of local mail delivery, Dovecot executes actions on incoming
# mail as defined in a "sieve" script.
#
# Dovecot's LDA role comes after spam filtering. Postfix hands mail off
# to Spamassassin which in turn hands it off to Dovecot. This all happens
# using the LMTP protocol.


# Setting a `postmaster_address` is required or LMTP won't start. An alias
# will be created automatically by our management daemon.
tools/editconf.py /etc/dovecot/conf.d/15-lda.conf \
		  postmaster_address=postmaster@$PRIMARY_HOSTNAME



######################################################################
#
# mail-users.sh
#
echo MIAC CONF mail-users.sh

#!/bin/bash
#
# User Authentication and Destination Validation
# ----------------------------------------------
#
# This script configures user authentication for Dovecot
# and Postfix (which relies on Dovecot) and destination
# validation by quering an Sqlite3 database of mail users.



######################################################################
#
# dkim.sh
#
echo MIAC CONF dkim.sh

#!/bin/bash
# OpenDKIM
# --------
#
# OpenDKIM provides a service that puts a DKIM signature on outbound mail.
#
# The DNS configuration for DKIM is done in the management daemon.



######################################################################
#
# spamassassin.sh
#
echo MIAC CONF spamassassin.sh

#!/bin/bash
# Spam filtering with spamassassin via spampd
# -------------------------------------------
#
# spampd sits between postfix and dovecot. It takes mail from postfix
# over the LMTP protocol, runs spamassassin on it, and then passes the
# message over LMTP to dovecot for local delivery.
#
# In order to move spam automatically into the Spam folder we use the dovecot sieve
# plugin.


# Authentication-Results SPF/Dmarc checks
# ---------------------------------------
# OpenDKIM and OpenDMARC are configured to validate and add "Authentication-Results: ..."
# headers by checking the sender's SPF & DMARC policies. Instead of blocking mail that fails
# these checks, we can use these headers to evaluate the mail as spam.
#
# Our custom rules are added to their own file so that an update to the deb package config
# does not remove our changes.
#
# We need to escape period's in $PRIMARY_HOSTNAME since spamassassin config uses regex.

escapedprimaryhostname="${PRIMARY_HOSTNAME//./\\.}"

cat > /etc/spamassassin/miab_spf_dmarc.cf << EOF
# Evaluate DMARC Authentication-Results
header DMARC_PASS Authentication-Results =~ /$escapedprimaryhostname; dmarc=pass/
describe DMARC_PASS DMARC check passed
score DMARC_PASS -0.1

header DMARC_NONE Authentication-Results =~ /$escapedprimaryhostname; dmarc=none/
describe DMARC_NONE DMARC record not found
score DMARC_NONE 0.1

header DMARC_FAIL_NONE Authentication-Results =~ /$escapedprimaryhostname; dmarc=fail \(p=none/
describe DMARC_FAIL_NONE DMARC check failed (p=none)
score DMARC_FAIL_NONE 2.0

header DMARC_FAIL_QUARANTINE Authentication-Results =~ /$escapedprimaryhostname; dmarc=fail \(p=quarantine/
describe DMARC_FAIL_QUARANTINE DMARC check failed (p=quarantine)
score DMARC_FAIL_QUARANTINE 5.0

header DMARC_FAIL_REJECT Authentication-Results =~ /$escapedprimaryhostname; dmarc=fail \(p=reject/
describe DMARC_FAIL_REJECT DMARC check failed (p=reject)
score DMARC_FAIL_REJECT 10.0

# Evaluate SPF Authentication-Results
header SPF_PASS Authentication-Results =~ /$escapedprimaryhostname; spf=pass/
describe SPF_PASS SPF check passed
score SPF_PASS -0.1

header SPF_NONE Authentication-Results =~ /$escapedprimaryhostname; spf=none/
describe SPF_NONE SPF record not found
score SPF_NONE 2.0

header SPF_FAIL Authentication-Results =~ /$escapedprimaryhostname; spf=fail/
describe SPF_FAIL SPF check failed
score SPF_FAIL 5.0
EOF



######################################################################
#
# web.sh
#
echo MIAC CONF web.sh

# Create the Mozilla Auto-configuration file which is exposed via the
# nginx configuration at /.well-known/autoconfig/mail/config-v1.1.xml.
# The format of the file is documented at:
# https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
# and https://developer.mozilla.org/en-US/docs/Mozilla/Thunderbird/Autoconfiguration/FileFormat/HowTo.
cat conf/mozilla-autoconfig.xml \
	| sed "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" \
	 > /var/lib/mailinabox/mozilla-autoconfig.xml
chmod a+r /var/lib/mailinabox/mozilla-autoconfig.xml

# Create a generic mta-sts.txt file which is exposed via the
# nginx configuration at /.well-known/mta-sts.txt
# more documentation is available on: 
# https://www.uriports.com/blog/mta-sts-explained/
# default mode is "enforce". In /etc/mailinabox.conf change
# "MTA_STS_MODE=testing" which means "Messages will be delivered
# as though there was no failure but a report will be sent if
# TLS-RPT is configured" if you are not sure you want this yet. Or "none".
PUNY_PRIMARY_HOSTNAME=$(echo "$PRIMARY_HOSTNAME" | idn2)
cat conf/mta-sts.txt \
        | sed "s/MODE/${MTA_STS_MODE}/" \
        | sed "s/PRIMARY_HOSTNAME/$PUNY_PRIMARY_HOSTNAME/" \
         > /var/lib/mailinabox/mta-sts.txt
chmod a+r /var/lib/mailinabox/mta-sts.txt



######################################################################
#
# webmail.sh
#
echo MIAC CONF webmail.sh

# ### Configuring Roundcube

# Generate a secret key of PHP-string-safe characters appropriate
# for the cipher algorithm selected below.
SECRET_KEY=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64 | sed s/=//g)


# Create a configuration file.
#
# For security, temp and log files are not stored in the default locations
# which are inside the roundcube sources directory. We put them instead
# in normal places.
cat > $RCM_CONFIG <<EOF;
<?php
/*
 * Do not edit. Written by Mail-in-a-Box. Regenerated on updates.
 */
\$config = array();
\$config['log_dir'] = '/var/log/roundcubemail/';
\$config['temp_dir'] = '/var/tmp/roundcubemail/';
\$config['db_dsnw'] = 'sqlite:///$STORAGE_ROOT/mail/roundcube/roundcube.sqlite?mode=0640';
\$config['imap_host'] = 'ssl://localhost:993';
\$config['imap_conn_options'] = array(
  'ssl'         => array(
     'verify_peer'  => false,
     'verify_peer_name'  => false,
   ),
 );
\$config['imap_timeout'] = 15;
\$config['smtp_host'] = 'tls://127.0.0.1';
\$config['smtp_conn_options'] = array(
  'ssl'         => array(
     'verify_peer'  => false,
     'verify_peer_name'  => false,
   ),
 );
\$config['support_url'] = 'https://mailinabox.email/';
\$config['product_name'] = '$PRIMARY_HOSTNAME Webmail';
\$config['cipher_method'] = 'AES-256-CBC'; # persistent login cookie and potentially other things
\$config['des_key'] = '$SECRET_KEY'; # 37 characters -> ~256 bits for AES-256, see above
\$config['plugins'] = array('html5_notifier', 'archive', 'zipdownload', 'password', 'managesieve', 'jqueryui', 'persistent_login', 'carddav');
\$config['skin'] = 'elastic';
\$config['login_autocomplete'] = 2;
\$config['login_username_filter'] = 'email';
\$config['password_charset'] = 'UTF-8';
\$config['junk_mbox'] = 'Spam';
/* ensure roudcube session id's aren't leaked to other parts of the server */
\$config['session_path'] = '/mail/';
/* prevent CSRF, requires php 7.3+ */
\$config['session_samesite'] = 'Strict';
?>
EOF

# Configure CardDav
cat > ${RCM_PLUGIN_DIR}/carddav/config.inc.php <<EOF;
<?php
/* Do not edit. Written by Mail-in-a-Box. Regenerated on updates. */
\$prefs['_GLOBAL']['hide_preferences'] = true;
\$prefs['_GLOBAL']['suppress_version_warning'] = true;
\$prefs['ownCloud'] = array(
	 'name'         =>  'ownCloud',
	 'username'     =>  '%u', // login username
	 'password'     =>  '%p', // login password
	 'url'          =>  'https://${PRIMARY_HOSTNAME}/cloud/remote.php/dav/addressbooks/users/%u/contacts/',
	 'active'       =>  true,
	 'readonly'     =>  false,
	 'refresh_time' => '02:00:00',
	 'fixed'        =>  array('username','password'),
	 'preemptive_auth' => '1',
	 'hide'        =>  false,
);
?>
EOF


# MIAC migration? semantics of ${RCM_DIR}/bin/updatedb.sh

# Run Roundcube database migration script (database is created if it does not exist)
php$PHP_VER ${RCM_DIR}/bin/updatedb.sh --dir ${RCM_DIR}/SQL --package roundcube
chown www-data:www-data $STORAGE_ROOT/mail/roundcube/roundcube.sqlite
chmod 664 $STORAGE_ROOT/mail/roundcube/roundcube.sqlite



######################################################################
#
# nextcloud.sh
#
echo MIAC CONF nextcloud.sh

# ### Configuring Nextcloud

# Setup Nextcloud if the Nextcloud database does not yet exist. Running setup when
# the database does exist wipes the database and user data.
if [ ! -f $STORAGE_ROOT/owncloud/owncloud.db ]; then
	# Create user data directory
	mkdir -p $STORAGE_ROOT/owncloud

	# Create an initial configuration file.
	instanceid=oc$(echo $PRIMARY_HOSTNAME | sha1sum | fold -w 10 | head -n 1)
	cat > $STORAGE_ROOT/owncloud/config.php <<EOF;
<?php
\$CONFIG = array (
  'datadirectory' => '$STORAGE_ROOT/owncloud',

  'instanceid' => '$instanceid',

  'forcessl' => true, # if unset/false, Nextcloud sends a HSTS=0 header, which conflicts with nginx config

  'overwritewebroot' => '/cloud',
  'overwrite.cli.url' => '/cloud',
  'user_backends' => array(
    array(
      'class' => '\OCA\UserExternal\IMAP',
      'arguments' => array(
        '127.0.0.1', 143, null, null, false, false
       ),
    ),
  ),
  'memcache.local' => '\OC\Memcache\APCu',
  'mail_smtpmode' => 'sendmail',
  'mail_smtpsecure' => '',
  'mail_smtpauthtype' => 'LOGIN',
  'mail_smtpauth' => false,
  'mail_smtphost' => '',
  'mail_smtpport' => '',
  'mail_smtpname' => '',
  'mail_smtppassword' => '',
  'mail_from_address' => 'owncloud',
);
?>
EOF

	# Create an auto-configuration file to fill in database settings
	# when the install script is run. Make an administrator account
	# here or else the install can't finish.
	# MIAC TODO: evaluate if MIAC_SSL_
	adminpassword=$(dd if=/dev/urandom bs=1 count=40 2>/dev/null | sha1sum | fold -w 30 | head -n 1)
	cat > /usr/local/lib/owncloud/config/autoconfig.php <<EOF;
<?php
\$AUTOCONFIG = array (
  # storage/database
  'directory' => '$STORAGE_ROOT/owncloud',
  'dbtype' => 'sqlite3',

  # create an administrator account with a random password so that
  # the user does not have to enter anything on first load of Nextcloud
  'adminlogin'    => 'root',
  'adminpass'     => '$adminpassword',
);
?>
EOF

	# Set permissions
	chown -R www-data.www-data $STORAGE_ROOT/owncloud /usr/local/lib/owncloud

	# Execute Nextcloud's setup step, which creates the Nextcloud sqlite database.
	# It also wipes it if it exists. And it updates config.php with database
	# settings and deletes the autoconfig.php file.
	(cd /usr/local/lib/owncloud; sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/index.php;)
fi

# Update config.php.
# * trusted_domains is reset to localhost by autoconfig starting with ownCloud 8.1.1,
#   so set it here. It also can change if the box's PRIMARY_HOSTNAME changes, so
#   this will make sure it has the right value.
# * Some settings weren't included in previous versions of Mail-in-a-Box.
# * We need to set the timezone to the system timezone to allow fail2ban to ban
#   users within the proper timeframe
# * We need to set the logdateformat to something that will work correctly with fail2ban
# * mail_domain' needs to be set every time we run the setup. Making sure we are setting
#   the correct domain name if the domain is being change from the previous setup.
# Use PHP to read the settings file, modify it, and write out the new settings array.
TIMEZONE=$(cat /etc/timezone)
CONFIG_TEMP=$(/bin/mktemp)
php$PHP_VER <<EOF > $CONFIG_TEMP && mv $CONFIG_TEMP $STORAGE_ROOT/owncloud/config.php;
<?php
include("$STORAGE_ROOT/owncloud/config.php");

\$CONFIG['config_is_read_only'] = true;

\$CONFIG['trusted_domains'] = array('$PRIMARY_HOSTNAME');

\$CONFIG['memcache.local'] = '\OC\Memcache\APCu';
\$CONFIG['overwrite.cli.url'] = '/cloud';
\$CONFIG['mail_from_address'] = 'administrator'; # just the local part, matches our master administrator address

\$CONFIG['logtimezone'] = '$TIMEZONE';
\$CONFIG['logdateformat'] = 'Y-m-d H:i:s';

\$CONFIG['mail_domain'] = '$PRIMARY_HOSTNAME';

\$CONFIG['user_backends'] = array(
  array(
    'class' => '\OCA\UserExternal\IMAP',
    'arguments' => array(
      '127.0.0.1', 143, null, null, false, false
    ),
  ),
);

echo "<?php\n\\\$CONFIG = ";
var_export(\$CONFIG);
echo ";";
?>
EOF
chown www-data.www-data $STORAGE_ROOT/owncloud/config.php

# Enable/disable apps. Note that this must be done after the Nextcloud setup.
# The firstrunwizard gave Josh all sorts of problems, so disabling that.
# user_external is what allows Nextcloud to use IMAP for login. The contacts
# and calendar apps are the extensions we really care about here.
hide_output sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/console.php app:disable firstrunwizard
hide_output sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/console.php app:enable user_external
hide_output sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/console.php app:enable contacts
hide_output sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/console.php app:enable calendar

# When upgrading, run the upgrade script again now that apps are enabled. It seems like
# the first upgrade at the top won't work because apps may be disabled during upgrade?
# Check for success (0=ok, 3=no upgrade needed).
sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/occ upgrade
if [ \( $? -ne 0 \) -a \( $? -ne 3 \) ]; then exit 1; fi



######################################################################
#
# zpush.sh
#
echo MIAC CONF zpush.sh

#!/bin/bash
#
# Z-Push: The Microsoft Exchange protocol server
# ----------------------------------------------
#
# Mostly for use on iOS which doesn't support IMAP IDLE.
#
# Although Ubuntu ships Z-Push (as d-push) it has a dependency on Apache
# so we won't install it that way.
#
# Thanks to http://frontender.ch/publikationen/push-mail-server-using-nginx-and-z-push.html.


sed -i "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" /usr/local/lib/z-push/autodiscover/config.php

sed -i "s^define('TIMEZONE', .*^define('TIMEZONE', '$(cat /etc/timezone)');^" /usr/local/lib/z-push/autodiscover/config.php



######################################################################
#
# management.sh
#
echo MIAC CONF management.sh

# Perform nightly tasks at 3am in system time: take a backup, run
# status checks and email the administrator any changes.

minute=$((RANDOM % 60))  # avoid overloading mailinabox.email
cat > /etc/cron.d/mailinabox-nightly << EOF;
# Mail-in-a-Box --- Do not edit / will be overwritten on update.
# Run nightly tasks: backup, status checks.
$minute 3 * * *	root	(cd $(pwd) && management/daily_tasks.sh)
EOF



######################################################################
#
# munin.sh
#
echo MIAC CONF munin.sh

# edit config
cat > /etc/munin/munin.conf <<EOF;
dbdir /var/lib/munin
htmldir /var/cache/munin/www
logdir /var/log/munin
rundir /var/run/munin
tmpldir /etc/munin/templates

includedir /etc/munin/munin-conf.d

# path dynazoom uses for requests
cgiurl_graph /admin/munin/cgi-graph

# a simple host tree
[$PRIMARY_HOSTNAME]
address 127.0.0.1

# send alerts to the following address
contacts admin
contact.admin.command mail -s "Munin notification \${var:host}" administrator@$PRIMARY_HOSTNAME
contact.admin.always_send warning critical
EOF

# ensure munin-node knows the name of this machine
# and reduce logging level to warning
tools/editconf.py /etc/munin/munin-node.conf -s \
	host_name=$PRIMARY_HOSTNAME \
	log_level=1

# Update the activated plugins through munin's autoconfiguration.
munin-node-configure --shell --remove-also 2>/dev/null | sh || /bin/true

# Deactivate monitoring of NTP peers. Not sure why anyone would want to monitor a NTP peer. The addresses seem to change
# (which is taken care of by munin-node-configure, but only when we re-run it.)
find /etc/munin/plugins/ -lname /usr/share/munin/plugins/ntp_ -print0 | xargs -0 /bin/rm -f

# Deactivate monitoring of network interfaces that are not up. Otherwise we can get a lot of empty charts.
for f in $(find /etc/munin/plugins/ \( -lname /usr/share/munin/plugins/if_ -o -lname /usr/share/munin/plugins/if_err_ -o -lname /usr/share/munin/plugins/bonding_err_ \)); do
	IF=$(echo $f | sed s/.*_//);
	if ! grep -qFx up /sys/class/net/$IF/operstate 2>/dev/null; then
		rm $f;
	fi;
done


# ensure success code when this script is sourced
/bin/true

