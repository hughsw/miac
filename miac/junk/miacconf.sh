datetime: 2022-11-05 13:16:39.259404   2022-11-05-1316-39
#!/bin/sh

# miacconf:  2022-11-05-1316-39

# miacconf: ['preflight.sh', 'functions.sh', 'locale.sh', 'mailinabox-bin.sh', 'migrate.sh', 'questions.sh', 'network-checks.sh', 'mailinabox-conf.sh', 'user-storage.sh', 'system.sh', 'resolv.sh', 'fail2ban.sh', 'ssl.sh', 'dns.sh', 'mail-postfix.sh', 'mail-dovecot.sh', 'mail-users.sh', 'dkim.sh', 'spamassassin.sh', 'web.sh', 'letsencrypt.sh', 'webmail.sh', 'nextcloud.sh', 'zpush.sh', 'management.sh', 'munin.sh', 'firstuser.sh']

# IF_MIAC_CONF_BEGIN / IF_MIAC_CONF_END


source miac-env.sh

source setup/functions.sh  # load our functions
source setup/locale.sh  # export locale env vars


# preflight.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# preflight.sh  END

# functions.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# functions.sh  END

# locale.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# locale.sh  END

# mailinabox-bin.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# mailinabox-bin.sh  END

# migrate.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not generic build

# Recall the last settings used if we're running this a second time.
if [ -f /etc/mailinabox.conf ]; then
	# Run any system migrations before proceeding. Since this is a second run,
	# we assume we have Python already installed.
	setup/migrate.py --migrate || exit 1

	# Load the old .conf file to get existing configuration options loaded
	# into variables with a DEFAULT_ prefix.
	cat /etc/mailinabox.conf | sed s/^/DEFAULT_/ > /tmp/mailinabox.prev.conf
	source /tmp/mailinabox.prev.conf
	rm -f /tmp/mailinabox.prev.conf
else
	FIRST_TIME_SETUP=1
fi

true
# migrate.sh  END

# questions.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not generic build

if [ -z "${NONINTERACTIVE:-}" ]; then
	# Install 'dialog' so we can ask the user questions. The original motivation for
	# this was being able to ask the user for input even if stdin has been redirected,
	# e.g. if we piped a bootstrapping install script to bash to get started. In that
	# case, the nifty '[ -t 0 ]' test won't work. But with Vagrant we must suppress so we
	# use a shell flag instead. Really suppress any output from installing dialog.
	#
	# Also install dependencies needed to validate the email address.
	if [ ! -f /usr/bin/dialog ] || [ ! -f /usr/bin/python3 ] || [ ! -f /usr/bin/pip3 ]; then
		echo Installing packages needed for setup...
		apt-get -q -q update
		apt_get_quiet install dialog python3 python3-pip  || exit 1
	fi

	# Installing email_validator is repeated in setup/management.sh, but in setup/management.sh
	# we install it inside a virtualenv. In this script, we don't have the virtualenv yet
	# so we install the python package globally.
	hide_output pip3 install "email_validator>=1.0.0" || exit 1

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

true
# questions.sh  END

# network-checks.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not generic build

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
# network-checks.sh  END

# mailinabox-conf.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation

    # Save the global options in /etc/mailinabox.conf so that standalone
    # tools know where to look for data. The default MTA_STS_MODE setting
    # is blank unless set by an environment variable, but see web.sh for
    # how that is interpreted.
    cat > /etc/mailinabox.conf << EOF
STORAGE_ROOT=$STORAGE_ROOT
PUBLIC_IPV6=$PUBLIC_IPV6
PRIVATE_IPV6=$PRIVATE_IPV6

STORAGE_USER=$STORAGE_USER
PRIMARY_HOSTNAME=$PRIMARY_HOSTNAME
PUBLIC_IP=$PUBLIC_IP
PRIVATE_IP=$PRIVATE_IP
MTA_STS_MODE=${DEFAULT_MTA_STS_MODE:-enforce}
EOF

# Load the confguration
source /etc/mailinabox.conf

true
# mailinabox-conf.sh  END

# user-storage.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

    # If the STORAGE_ROOT is missing the mailinabox.version file that lists a
    # migration (schema) number for the files stored there, assume this is a fresh
    # installation to that directory and write the file to contain the current
    # migration number for this version of Mail-in-a-Box.
    if ! id -u $STORAGE_USER >/dev/null 2>&1; then
	useradd $STORAGE_USER
    fi

    # MIAC_MIGRATE ?

    if [ ! -f $STORAGE_ROOT/mailinabox.version ]; then
	setup/migrate.py --current > $STORAGE_ROOT/mailinabox.version
	chown $STORAGE_USER:$STORAGE_USER $STORAGE_ROOT/mailinabox.version
    fi

true
# user-storage.sh  END

# system.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# system.sh  END

# resolv.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# resolv.sh  END

# fail2ban.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build
    cat conf/fail2ban/jails.conf \
	| sed "s/PUBLIC_IPV6/$PUBLIC_IPV6/g" \
	| sed "s/PUBLIC_IP/$PUBLIC_IP/g" \
	| sed "s#STORAGE_ROOT#$STORAGE_ROOT#" \
	      > /etc/fail2ban/jail.d/mailinabox.conf
true
# fail2ban.sh  END

# ssl.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

    # Generate a self-signed SSL certificate because things like nginx, dovecot,
    # etc. won't even start without some certificate in place, and we need nginx
    # so we can offer the user a control panel to install a better certificate.
    if [ ! -f $STORAGE_ROOT/ssl/ssl_certificate.pem ]; then
	# Generate a certificate signing request.
	CSR=/tmp/ssl_cert_sign_req-$$.csr
	hide_output \
	    openssl req -new -key $STORAGE_ROOT/ssl/ssl_private_key.pem -out $CSR \
	    -sha256 -subj "/CN=$PRIMARY_HOSTNAME"

	# Generate the self-signed certificate.
	CERT=$STORAGE_ROOT/ssl/$PRIMARY_HOSTNAME-selfsigned-$(date --rfc-3339=date | sed s/-//g).pem
	hide_output \
	    openssl x509 -req -days 365 \
	    -in $CSR -signkey $STORAGE_ROOT/ssl/ssl_private_key.pem -out $CERT

	# Delete the certificate signing request because it has no other purpose.
	rm -f $CSR

	# Symlink the certificate into the system certificate path, so system services
	# can find it.
	ln -s $CERT $STORAGE_ROOT/ssl/ssl_certificate.pem
    fi

    # Generate some Diffie-Hellman cipher bits.
    # openssl's default bit length for this is 1024 bits, but we'll create
    # 2048 bits of bits per the latest recommendations.
    if [ ! -f $STORAGE_ROOT/ssl/dh2048.pem ]; then
	openssl dhparam -out $STORAGE_ROOT/ssl/dh2048.pem 2048
    fi
true
# ssl.sh  END

# dns.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

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

    # Configuring a specific installation, not just a generic build

# TLDs, registrars, and validating nameservers don't all support the same algorithms,
# so we'll generate keys using a few different algorithms so that dns_update.py can
# choose which algorithm to use when generating the zonefiles. See #1953 for recent
# discussion. File for previously used algorithms (i.e. RSASHA1-NSEC3-SHA1) may still
# be in the output directory, and we'll continue to support signing zones with them
# so that trust isn't broken with deployed DS records, but we won't generate those
# keys on new systems.
FIRST=1 #NODOC
for algo in RSASHA256 ECDSAP256SHA256; do
if [ ! -f "$STORAGE_ROOT/dns/dnssec/$algo.conf" ]; then
	if [ $FIRST == 1 ]; then
		echo "Generating DNSSEC signing keys..."
		FIRST=0 #NODOC
	fi

	# Create the Key-Signing Key (KSK) (with `-k`) which is the so-called
	# Secure Entry Point. The domain name we provide ("_domain_") doesn't
	# matter -- we'll use the same keys for all our domains.
	#
	# `ldns-keygen` outputs the new key's filename to stdout, which
	# we're capturing into the `KSK` variable.
	#
	# ldns-keygen uses /dev/random for generating random numbers by default.
	# This is slow and unecessary if we ensure /dev/urandom is seeded properly,
	# so we use /dev/urandom. See system.sh for an explanation. See #596, #115.
	# (This previously used -b 2048 but it's unclear if this setting makes sense
	# for non-RSA keys, so it's removed. The RSA-based keys are not recommended
	# anymore anyway.)
	KSK=$(umask 077; cd $STORAGE_ROOT/dns/dnssec; ldns-keygen -r /dev/urandom -a $algo -k _domain_);

	# Now create a Zone-Signing Key (ZSK) which is expected to be
	# rotated more often than a KSK, although we have no plans to
	# rotate it (and doing so would be difficult to do without
	# disturbing DNS availability.) Omit `-k`.
	# (This previously used -b 1024 but it's unclear if this setting makes sense
	# for non-RSA keys, so it's removed.)
	ZSK=$(umask 077; cd $STORAGE_ROOT/dns/dnssec; ldns-keygen -r /dev/urandom -a $algo _domain_);

	# These generate two sets of files like:
	#
	# * `K_domain_.+007+08882.ds`: DS record normally provided to domain name registrar (but it's actually invalid with `_domain_` so we don't use this file)
	# * `K_domain_.+007+08882.key`: public key
	# * `K_domain_.+007+08882.private`: private key (secret!)

	# The filenames are unpredictable and encode the key generation
	# options. So we'll store the names of the files we just generated.
	# We might have multiple keys down the road. This will identify
	# what keys are the current keys.
	cat > $STORAGE_ROOT/dns/dnssec/$algo.conf << EOF;
KSK=$KSK
ZSK=$ZSK
EOF
fi

	# And loop to do the next algorithm...
done

true
# dns.sh  END

# mail-postfix.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

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
true
# mail-postfix.sh  END

# mail-dovecot.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

    # Setting a `postmaster_address` is required or LMTP won't start. An alias
    # will be created automatically by our management daemon.
    tools/editconf.py /etc/dovecot/conf.d/15-lda.conf \
		      postmaster_address=postmaster@$PRIMARY_HOSTNAME
true
# mail-dovecot.sh  END

# mail-users.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# mail-users.sh  END

# dkim.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# dkim.sh  END

# spamassassin.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

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
true
# spamassassin.sh  END

# web.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

cat conf/ios-profile.xml \
	| sed "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" \
	| sed "s/UUID1/$(cat /proc/sys/kernel/random/uuid)/" \
	| sed "s/UUID2/$(cat /proc/sys/kernel/random/uuid)/" \
	| sed "s/UUID3/$(cat /proc/sys/kernel/random/uuid)/" \
	| sed "s/UUID4/$(cat /proc/sys/kernel/random/uuid)/" \
	 > /var/lib/mailinabox/mobileconfig.xml
chmod a+r /var/lib/mailinabox/mobileconfig.xml

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

    # Configuring a specific installation, not just a generic build
chown -R $STORAGE_USER $STORAGE_ROOT/www
true
# web.sh  END

# letsencrypt.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

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

true
# letsencrypt.sh  END

# webmail.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
RCM_DIR=/usr/local/lib/roundcubemail
RCM_PLUGIN_DIR=${RCM_DIR}/plugins
RCM_CONFIG=${RCM_DIR}/config/config.inc.php
    # Configuring a specific installation, not just a generic build

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

    # Configuring a specific installation, not just a generic build

# Run Roundcube database migration script (database is created if it does not exist)
php$PHP_VER ${RCM_DIR}/bin/updatedb.sh --dir ${RCM_DIR}/SQL --package roundcube
chown www-data:www-data $STORAGE_ROOT/mail/roundcube/roundcube.sqlite
chmod 664 $STORAGE_ROOT/mail/roundcube/roundcube.sqlite

true
# webmail.sh  END

# nextcloud.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

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

# Disable default apps that we don't support
sudo -u www-data \
	php$PHP_VER /usr/local/lib/owncloud/occ app:disable photos dashboard activity \
	| (grep -v "No such app enabled" || /bin/true)

# Set PHP FPM values to support large file uploads
# (semicolon is the comment character in this file, hashes produce deprecation warnings)
tools/editconf.py /etc/php/$PHP_VER/fpm/php.ini -c ';' \
	upload_max_filesize=16G \
	post_max_size=16G \
	output_buffering=16384 \
	memory_limit=512M \
	max_execution_time=600 \
	short_open_tag=On

# Set Nextcloud recommended opcache settings
tools/editconf.py /etc/php/$PHP_VER/cli/conf.d/10-opcache.ini -c ';' \
	opcache.enable=1 \
	opcache.enable_cli=1 \
	opcache.interned_strings_buffer=8 \
	opcache.max_accelerated_files=10000 \
	opcache.memory_consumption=128 \
	opcache.save_comments=1 \
	opcache.revalidate_freq=1

# Migrate users_external data from <0.6.0 to version 3.0.0 (see https://github.com/nextcloud/user_external).
# This version was probably in use in Mail-in-a-Box v0.41 (February 26, 2019) and earlier.
# We moved to v0.6.3 in 193763f8. Ignore errors - maybe there are duplicated users with the
# correct backend already.
sqlite3 $STORAGE_ROOT/owncloud/owncloud.db "UPDATE oc_users_external SET backend='127.0.0.1';" || /bin/true

true
# nextcloud.sh  END

# zpush.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

sed -i "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" /usr/local/lib/z-push/autodiscover/config.php

sed -i "s^define('TIMEZONE', .*^define('TIMEZONE', '$(cat /etc/timezone)');^" /usr/local/lib/z-push/autodiscover/config.php

true
# zpush.sh  END

# management.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# management.sh  END

# munin.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
    # Configuring a specific installation, not just a generic build

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
# (which is taken care of my munin-node-configure, but only when we re-run it.)
find /etc/munin/plugins/ -lname /usr/share/munin/plugins/ntp_ -print0 | xargs -0 /bin/rm -f

# Deactivate monitoring of network interfaces that are not up. Otherwise we can get a lot of empty charts.
for f in $(find /etc/munin/plugins/ \( -lname /usr/share/munin/plugins/if_ -o -lname /usr/share/munin/plugins/if_err_ -o -lname /usr/share/munin/plugins/bonding_err_ \)); do
	IF=$(echo $f | sed s/.*_//);
	if ! grep -qFx up /sys/class/net/$IF/operstate 2>/dev/null; then
		rm $f;
	fi;
done

true
# munin.sh  END

# firstuser.sh  BEGIN >>>>>>>>>>>>>>>>>>>>
true
# firstuser.sh  END
