# MIAC: GENERIC

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# mailinabox-bin.sh
#
echo MIAC GENERIC mailinabox-bin.sh

# Put a start script in a global location. We tell the user to run 'mailinabox'
# in the first dialog prompt, so we should do this before that starts.
cat > /usr/local/bin/mailinabox << EOF;
#!/bin/bash
cd $(pwd)
source setup/start.sh
EOF
chmod +x /usr/local/bin/mailinabox



######################################################################
#
# mailinabox-conf.sh
#
echo MIAC GENERIC mailinabox-conf.sh

# MIAC TODO: figure out env handling

cat > /etc/mailinabox.conf <<EOF
STORAGE_ROOT=$STORAGE_ROOT
STORAGE_USER=$STORAGE_USER
PUBLIC_IPV6=
PRIVATE_IPV6=
EOF

# Load the confguration
source /etc/mailinabox.conf



######################################################################
#
# user-storage.sh
#
echo MIAC GENERIC user-storage.sh

# Ensure the STORAGE_ROOT directory, and STORAGE_USER
#
# Set the directory and all of its parent directories' permissions to world
# readable since it holds files owned by different processes.
mkdir -p $STORAGE_ROOT

f=$STORAGE_ROOT
while [[ $f != / ]]; do
    chmod a+rx $f
    f=$(dirname $f)
done


# If the STORAGE_ROOT is missing the mailinabox.version file that lists a
# migration (schema) number for the files stored there, assume this is a fresh
# installation to that directory and write the file to contain the current
# migration number for this version of Mail-in-a-Box.
if ! id -u $STORAGE_USER >/dev/null 2>&1; then
    useradd $STORAGE_USER
fi

# MIAC migrate/version/state semantics
# MIAC the following is not a migration, it's a code introspection to determine code's version number

if [ ! -f $STORAGE_ROOT/mailinabox.version ]; then
    setup/migrate.py --current > $STORAGE_ROOT/mailinabox.version
    chown $STORAGE_USER:$STORAGE_USER $STORAGE_ROOT/mailinabox.version
fi



######################################################################
#
# system.sh
#
echo MIAC GENERIC system.sh

# ### Fix permissions

# The default Ubuntu Bionic image on Scaleway throws warnings during setup about incorrect
# permissions (group writeable) set on the following directories.

chmod g-w /etc /etc/default /usr

# ### Add swap space to the system

# If the physical memory of the system is below 2GB it is wise to create a
# swap file. This will make the system more resiliant to memory spikes and
# prevent for instance spam filtering from crashing

# We will create a 1G file, this should be a good balance between disk usage
# and buffers for the system. We will only allocate this file if there is more
# than 5GB of disk space available

# The following checks are performed:
# - Check if swap is currently mountend by looking at /proc/swaps
# - Check if the user intents to activate swap on next boot by checking fstab entries.
# - Check if a swapfile already exists
# - Check if the root file system is not btrfs, might be an incompatible version with
#   swapfiles. User should hanle it them selves.
# - Check the memory requirements
# - Check available diskspace

# See https://www.digitalocean.com/community/tutorials/how-to-add-swap-on-ubuntu-14-04
# for reference

SWAP_MOUNTED=$(cat /proc/swaps | tail -n+2)
SWAP_IN_FSTAB=$(grep "swap" /etc/fstab || /bin/true)
ROOT_IS_BTRFS=$(grep "\/ .*btrfs" /proc/mounts || /bin/true)
TOTAL_PHYSICAL_MEM=$(head -n 1 /proc/meminfo | awk '{print $2}' || /bin/true)
AVAILABLE_DISK_SPACE=$(df / --output=avail | tail -n 1)
if
	[ -z "$SWAP_MOUNTED" ] &&
	[ -z "$SWAP_IN_FSTAB" ] &&
	[ ! -e /swapfile ] &&
	[ -z "$ROOT_IS_BTRFS" ] &&
	[ $TOTAL_PHYSICAL_MEM -lt 1900000 ] &&
	[ $AVAILABLE_DISK_SPACE -gt 5242880 ]
then
	echo "Adding a swap file to the system..."

	# Allocate and activate the swap file. Allocate in 1KB chuncks
	# doing it in one go, could fail on low memory systems
	dd if=/dev/zero of=/swapfile bs=1024 count=$[1024*1024] status=none
	if [ -e /swapfile ]; then
		chmod 600 /swapfile
		hide_output mkswap /swapfile
		swapon /swapfile
	fi

	# Check if swap is mounted then activate on boot
	if swapon -s | grep -q "\/swapfile"; then
		echo "/swapfile   none    swap    sw    0   0" >> /etc/fstab
	else
		echo "ERROR: Swap allocation failed"
	fi
fi

# ### Set log retention policy.

# Set the systemd journal log retention from infinite to 10 days,
# since over time the logs take up a large amount of space.
# (See https://discourse.mailinabox.email/t/journalctl-reclaim-space-on-small-mailinabox/6728/11.)
tools/editconf.py /etc/systemd/journald.conf MaxRetentionSec=10day


# ### Suppress Upgrade Prompts
# When Ubuntu 20 comes out, we don't want users to be prompted to upgrade,
# because we don't yet support it.
if [ -f /etc/update-manager/release-upgrades ]; then
	tools/editconf.py /etc/update-manager/release-upgrades Prompt=never
	rm -f /var/lib/ubuntu-release-upgrader/release-upgrade-available
fi


# ### Package maintenance
#
# Allow apt to install system updates automatically every day.

cat > /etc/apt/apt.conf.d/02periodic <<EOF;
APT::Periodic::MaxAge "7";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "0";
EOF



######################################################################
#
# resolv.sh
#
echo MIAC GENERIC resolv.sh

# ### Local DNS Service

# Install a local recursive DNS server --- i.e. for DNS queries made by
# local services running on this machine.
#
# (This is unrelated to the box's public, non-recursive DNS server that
# answers remote queries about domain names hosted on this box. For that
# see dns.sh.)
#
# The default systemd-resolved service provides local DNS name resolution. By default it
# is a recursive stub nameserver, which means it simply relays requests to an
# external nameserver, usually provided by your ISP or configured in /etc/systemd/resolved.conf.
#
# This won't work for us for three reasons.
#
# 1) We have higher security goals --- we want DNSSEC to be enforced on all
#    DNS queries (some upstream DNS servers do, some don't).
# 2) We will configure postfix to use DANE, which uses DNSSEC to find TLS
#    certificates for remote servers. DNSSEC validation *must* be performed
#    locally because we can't trust an unencrypted connection to an external
#    DNS server.
# 3) DNS-based mail server blacklists (RBLs) typically block large ISP
#    DNS servers because they only provide free data to small users. Since
#    we use RBLs to block incoming mail from blacklisted IP addresses,
#    we have to run our own DNS server. See #1424.
#
# systemd-resolved has a setting to perform local DNSSEC validation on all
# requests (in /etc/systemd/resolved.conf, set DNSSEC=yes), but because it's
# a stub server the main part of a request still goes through an upstream
# DNS server, which won't work for RBLs. So we really need a local recursive
# nameserver.
#
# We'll install `bind9`, which as packaged for Ubuntu, has DNSSEC enabled by default via "dnssec-validation auto".
# We'll have it be bound to 127.0.0.1 so that it does not interfere with
# the public, recursive nameserver `nsd` bound to the public ethernet interfaces.
#
# About the settings:
#
# * Adding -4 to OPTIONS will have `bind9` not listen on IPv6 addresses
#   so that we're sure there's no conflict with nsd, our public domain
#   name server, on IPV6.
# * The listen-on directive in named.conf.options restricts `bind9` to
#   binding to the loopback interface instead of all interfaces.
# * The max-recursion-queries directive increases the maximum number of iterative queries.
#  	If more queries than specified are sent, bind9 returns SERVFAIL. After flushing the cache during system checks,
#	we ran into the limit thus we are increasing it from 75 (default value) to 100.

tools/editconf.py /etc/default/named \
	"OPTIONS=\"-u bind -4\""
if ! grep -q "listen-on " /etc/bind/named.conf.options; then
	# Add a listen-on directive if it doesn't exist inside the options block.
	sed -i "s/^}/\n\tlisten-on { 127.0.0.1; };\n}/" /etc/bind/named.conf.options
fi
if ! grep -q "max-recursion-queries " /etc/bind/named.conf.options; then
	# Add a max-recursion-queries directive if it doesn't exist inside the options block.
	sed -i "s/^}/\n\tmax-recursion-queries 100;\n}/" /etc/bind/named.conf.options
fi



######################################################################
#
# fail2ban.sh
#
echo MIAC GENERIC fail2ban.sh

cp -f conf/fail2ban/filter.d/* /etc/fail2ban/filter.d/



######################################################################
#
# ssl.sh
#
echo MIAC GENERIC ssl.sh

# Create a directory to store TLS-related things like "SSL" certificates.

mkdir -p $STORAGE_ROOT/ssl



######################################################################
#
# dns.sh
#
echo MIAC GENERIC dns.sh

# Prepare nsd's configuration.
# We configure nsd before installation as we only want it to bind to some addresses
# and it otherwise will have port / bind conflicts with bind9 used as the local resolver
mkdir -p /var/run/nsd
mkdir -p /etc/nsd
mkdir -p /etc/nsd/zones
touch /etc/nsd/zones.conf


# Remove the old location of zones.conf that we generate. It will
# now be stored in /etc/nsd/nsd.conf.d.
rm -f /etc/nsd/zones.conf

# Add log rotation
cat > /etc/logrotate.d/nsd <<EOF;
/var/log/nsd.log {
  weekly
  missingok
  rotate 12
  compress
  delaycompress
  notifempty
}
EOF

mkdir -p "$STORAGE_ROOT/dns/dnssec";



######################################################################
#
# mail-postfix.sh
#
echo MIAC GENERIC mail-postfix.sh

# Tweak some queue settings:
# * Inform users when their e-mail delivery is delayed more than 3 hours (default is not to warn).
# * Stop trying to send an undeliverable e-mail after 2 days (instead of 5), and for bounce messages just try for 1 day.
tools/editconf.py /etc/postfix/main.cf \
	delay_warning_time=3h \
	maximal_queue_lifetime=2d \
	bounce_queue_lifetime=1d

# ### Outgoing Mail

# Enable the 'submission' ports 465 and 587 and tweak their settings.
#
# * Enable authentication. It's disabled globally so that it is disabled on port 25,
#   so we need to explicitly enable it here.
# * Do not add the OpenDMAC Authentication-Results header. That should only be added
#   on incoming mail. Omit the OpenDMARC milter by re-setting smtpd_milters to the
#   OpenDKIM milter only. See dkim.sh.
# * Even though we dont allow auth over non-TLS connections (smtpd_tls_auth_only below, and without auth the client cant
#   send outbound mail), don't allow non-TLS mail submission on this port anyway to prevent accidental misconfiguration.
#   Setting smtpd_tls_security_level=encrypt also triggers the use of the 'mandatory' settings below (but this is ignored with smtpd_tls_wrappermode=yes.)
# * Give it a different name in syslog to distinguish it from the port 25 smtpd server.
# * Add a new cleanup service specific to the submission service ('authclean')
#   that filters out privacy-sensitive headers on mail being sent out by
#   authenticated users.  By default Postfix also applies this to attached
#   emails but we turn this off by setting nested_header_checks empty.
tools/editconf.py /etc/postfix/master.cf -s -w \
	"smtps=inet n       -       -       -       -       smtpd
	  -o smtpd_tls_wrappermode=yes
	  -o smtpd_sasl_auth_enable=yes
	  -o syslog_name=postfix/submission
	  -o smtpd_milters=inet:127.0.0.1:8891
	  -o cleanup_service_name=authclean" \
	"submission=inet n       -       -       -       -       smtpd
	  -o smtpd_sasl_auth_enable=yes
	  -o syslog_name=postfix/submission
	  -o smtpd_milters=inet:127.0.0.1:8891
	  -o smtpd_tls_security_level=encrypt
	  -o cleanup_service_name=authclean" \
	"authclean=unix  n       -       -       -       0       cleanup
	  -o header_checks=pcre:/etc/postfix/outgoing_mail_header_filters
	  -o nested_header_checks="

# Install the `outgoing_mail_header_filters` file required by the new 'authclean' service.
cp conf/postfix_outgoing_mail_header_filters /etc/postfix/outgoing_mail_header_filters


# Enable TLS on incoming connections. It is not required on port 25, allowing for opportunistic
# encryption. On ports 465 and 587 it is mandatory (see above). Shared and non-shared settings are
# given here. Shared settings include:
# * Require TLS before a user is allowed to authenticate.
# * Set the path to the server TLS certificate and 2048-bit DH parameters for old DH ciphers.
# For port 25 only:
# * Disable extremely old versions of TLS and extremely unsafe ciphers, but some mail servers out in
#   the world are very far behind and if we disable too much, they may not be able to use TLS and
#   won't fall back to cleartext. So we don't disable too much. smtpd_tls_exclude_ciphers applies to
#   both port 25 and port 587, but because we override the cipher list for both, it probably isn't used.
#   Use Mozilla's "Old" recommendations at https://ssl-config.mozilla.org/#server=postfix&server-version=3.3.0&config=old&openssl-version=1.1.1
tools/editconf.py /etc/postfix/main.cf \
	smtpd_tls_security_level=may\
	smtpd_tls_auth_only=yes \
	smtpd_tls_cert_file=$STORAGE_ROOT/ssl/ssl_certificate.pem \
	smtpd_tls_key_file=$STORAGE_ROOT/ssl/ssl_private_key.pem \
	smtpd_tls_dh1024_param_file=$STORAGE_ROOT/ssl/dh2048.pem \
	smtpd_tls_protocols="!SSLv2,!SSLv3" \
	smtpd_tls_ciphers=medium \
	tls_medium_cipherlist=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA \
	smtpd_tls_exclude_ciphers=aNULL,RC4 \
	tls_preempt_cipherlist=no \
	smtpd_tls_received_header=yes

# For ports 465/587 (via the 'mandatory' settings):
# * Use Mozilla's "Intermediate" TLS recommendations from https://ssl-config.mozilla.org/#server=postfix&server-version=3.3.0&config=intermediate&openssl-version=1.1.1
#   using and overriding the "high" cipher list so we don't conflict with the more permissive settings for port 25.
tools/editconf.py /etc/postfix/main.cf \
	smtpd_tls_mandatory_protocols="!SSLv2,!SSLv3,!TLSv1,!TLSv1.1" \
	smtpd_tls_mandatory_ciphers=high \
	tls_high_cipherlist=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384 \
	smtpd_tls_mandatory_exclude_ciphers=aNULL,DES,3DES,MD5,DES+MD5,RC4

# Prevent non-authenticated users from sending mail that requires being
# relayed elsewhere. We don't want to be an "open relay". On outbound
# mail, require one of:
#
# * `permit_sasl_authenticated`: Authenticated users (i.e. on port 465/587).
# * `permit_mynetworks`: Mail that originates locally.
# * `reject_unauth_destination`: No one else. (Permits mail whose destination is local and rejects other mail.)
tools/editconf.py /etc/postfix/main.cf \
	smtpd_relay_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination


# ### DANE

# When connecting to remote SMTP servers, prefer TLS and use DANE if available.
#
# Prefering ("opportunistic") TLS means Postfix will use TLS if the remote end
# offers it, otherwise it will transmit the message in the clear. Postfix will
# accept whatever SSL certificate the remote end provides. Opportunistic TLS
# protects against passive easvesdropping (but not man-in-the-middle attacks).
# Since we'd rather have poor encryption than none at all, we use Mozilla's
# "Old" recommendations at https://ssl-config.mozilla.org/#server=postfix&server-version=3.3.0&config=old&openssl-version=1.1.1
# for opportunistic encryption but "Intermediate" recommendations when DANE
# is used (see next and above). The cipher lists are set above.

# DANE takes this a step further:
# Postfix queries DNS for the TLSA record on the destination MX host. If no TLSA records are found,
# then opportunistic TLS is used. Otherwise the server certificate must match the TLSA records
# or else the mail bounces. TLSA also requires DNSSEC on the MX host. Postfix doesn't do DNSSEC
# itself but assumes the system's nameserver does and reports DNSSEC status. Thus this also
# relies on our local DNS server (see system.sh) and `smtp_dns_support_level=dnssec`.
#
# The `smtp_tls_CAfile` is superflous, but it eliminates warnings in the logs about untrusted certs,
# which we don't care about seeing because Postfix is doing opportunistic TLS anyway. Better to encrypt,
# even if we don't know if it's to the right party, than to not encrypt at all. Instead we'll
# now see notices about trusted certs. The CA file is provided by the package `ca-certificates`.
tools/editconf.py /etc/postfix/main.cf \
	smtp_tls_protocols=\!SSLv2,\!SSLv3 \
	smtp_tls_ciphers=medium \
	smtp_tls_exclude_ciphers=aNULL,RC4 \
	smtp_tls_security_level=dane \
	smtp_dns_support_level=dnssec \
	smtp_tls_mandatory_protocols="!SSLv2,!SSLv3,!TLSv1,!TLSv1.1" \
	smtp_tls_mandatory_ciphers=high \
	smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt \
	smtp_tls_loglevel=2

# ### Incoming Mail

# Pass mail to spampd, which acts as the local delivery agent (LDA),
# which then passes the mail over to the Dovecot LMTP server after.
# spampd runs on port 10025 by default.
#
# In a basic setup we would pass mail directly to Dovecot by setting
# virtual_transport to `lmtp:unix:private/dovecot-lmtp`.
tools/editconf.py /etc/postfix/main.cf "virtual_transport=lmtp:[127.0.0.1]:10025"
# Clear the lmtp_destination_recipient_limit setting which in previous
# versions of Mail-in-a-Box was set to 1 because of a spampd bug.
# See https://github.com/mail-in-a-box/mailinabox/issues/1523.
tools/editconf.py /etc/postfix/main.cf  -e lmtp_destination_recipient_limit=


# Who can send mail to us? Some basic filters.
#
# * `reject_non_fqdn_sender`: Reject not-nice-looking return paths.
# * `reject_unknown_sender_domain`: Reject return paths with invalid domains.
# * `reject_authenticated_sender_login_mismatch`: Reject if mail FROM address does not match the client SASL login
# * `reject_rhsbl_sender`: Reject return paths that use blacklisted domains.
# * `permit_sasl_authenticated`: Authenticated users (i.e. on port 587) can skip further checks.
# * `permit_mynetworks`: Mail that originates locally can skip further checks.
# * `reject_rbl_client`: Reject connections from IP addresses blacklisted in zen.spamhaus.org
# * `reject_unlisted_recipient`: Although Postfix will reject mail to unknown recipients, it's nicer to reject such mail ahead of greylisting rather than after.
# * `check_policy_service`: Apply greylisting using postgrey.
#
# Notes: #NODOC
# permit_dnswl_client can pass through mail from whitelisted IP addresses, which would be good to put before greylisting #NODOC
# so these IPs get mail delivered quickly. But when an IP is not listed in the permit_dnswl_client list (i.e. it is not #NODOC
# whitelisted) then postfix does a DEFER_IF_REJECT, which results in all "unknown user" sorts of messages turning into #NODOC
# "450 4.7.1 Client host rejected: Service unavailable". This is a retry code, so the mail doesn't properly bounce. #NODOC
tools/editconf.py /etc/postfix/main.cf \
	smtpd_sender_restrictions="reject_non_fqdn_sender,reject_unknown_sender_domain,reject_authenticated_sender_login_mismatch,reject_rhsbl_sender dbl.spamhaus.org" \
	smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,"reject_rbl_client zen.spamhaus.org",reject_unlisted_recipient,"check_policy_service inet:127.0.0.1:10023"

# Postfix connects to Postgrey on the 127.0.0.1 interface specifically. Ensure that
# Postgrey listens on the same interface (and not IPv6, for instance).
# A lot of legit mail servers try to resend before 300 seconds.
# As a matter of fact RFC is not strict about retry timer so postfix and
# other MTA have their own intervals. To fix the problem of receiving
# e-mails really latter, delay of greylisting has been set to
# 180 seconds (default is 300 seconds). We will move the postgrey database
# under $STORAGE_ROOT. This prevents a "warming up" that would have occured
# previously with a migrated or reinstalled OS.  We will specify this new path
# with the --dbdir=... option. Arguments within POSTGREY_OPTS can not have spaces,
# including dbdir. This is due to the way the init script sources the
# /etc/default/postgrey file. --dbdir=... either needs to be a path without spaces
# (luckily $STORAGE_ROOT does not currently work with spaces), or it needs to be a
# symlink without spaces that can point to a folder with spaces).  We'll just assume
# $STORAGE_ROOT won't have spaces to simplify things.
tools/editconf.py /etc/default/postgrey \
	POSTGREY_OPTS=\""--inet=127.0.0.1:10023 --delay=180 --dbdir=$STORAGE_ROOT/mail/postgrey/db"\"


# If the $STORAGE_ROOT/mail/postgrey is empty, copy the postgrey database over from the old location
if [ ! -d $STORAGE_ROOT/mail/postgrey/db ]; then



	# Ensure the new paths for postgrey db exists
	mkdir -p $STORAGE_ROOT/mail/postgrey/db
	# Move over database files
	mv /var/lib/postgrey/* $STORAGE_ROOT/mail/postgrey/db/ || true
fi
# Ensure permissions are set
chown -R postgrey:postgrey $STORAGE_ROOT/mail/postgrey/
chmod 700 $STORAGE_ROOT/mail/postgrey/{,db}

# We are going to setup a newer whitelist for postgrey, the version included in the distribution is old
cat > /etc/cron.daily/mailinabox-postgrey-whitelist << EOF;
#!/bin/bash

# Mail-in-a-Box

# check we have a postgrey_whitelist_clients file and that it is not older than 28 days
if [ ! -f /etc/postgrey/whitelist_clients ] || find /etc/postgrey/whitelist_clients -mtime +28 | grep -q '.' ; then
    # ok we need to update the file, so lets try to fetch it
    if curl https://postgrey.schweikert.ch/pub/postgrey_whitelist_clients --output /tmp/postgrey_whitelist_clients -sS --fail > /dev/null 2>&1 ; then
        # if fetching hasn't failed yet then check it is a plain text file
        # curl manual states that --fail sometimes still produces output
        # this final check will at least check the output is not html
        # before moving it into place
        if [ "\$(file -b --mime-type /tmp/postgrey_whitelist_clients)" == "text/plain" ]; then
            mv /tmp/postgrey_whitelist_clients /etc/postgrey/whitelist_clients
            service postgrey restart
	else
            rm /tmp/postgrey_whitelist_clients
        fi
    fi
fi
EOF
chmod +x /etc/cron.daily/mailinabox-postgrey-whitelist




# Increase the message size limit from 10MB to 128MB.
# The same limit is specified in nginx.conf for mail submitted via webmail and Z-Push.
tools/editconf.py /etc/postfix/main.cf \
	message_size_limit=134217728



######################################################################
#
# mail-dovecot.sh
#
echo MIAC GENERIC mail-dovecot.sh

# The `dovecot-imapd`, `dovecot-pop3d`, and `dovecot-lmtpd` packages automatically
# enable IMAP, POP and LMTP protocols.

# Set basic daemon options.

# The `default_process_limit` is 100, which constrains the total number
# of active IMAP connections (at, say, 5 open connections per user that
# would be 20 users). Set it to 250 times the number of cores this
# machine has, so on a two-core machine that's 500 processes/100 users).
# The `default_vsz_limit` is the maximum amount of virtual memory that
# can be allocated. It should be set *reasonably high* to avoid allocation
# issues with larger mailboxes. We're setting it to 1/3 of the total
# available memory (physical mem + swap) to be sure.
# See here for discussion:
# - https://www.dovecot.org/list/dovecot/2012-August/137569.html
# - https://www.dovecot.org/list/dovecot/2011-December/132455.html
tools/editconf.py /etc/dovecot/conf.d/10-master.conf \
	default_process_limit=$(echo "$(nproc) * 250" | bc) \
	default_vsz_limit=$(echo "$(free -tm  | tail -1 | awk '{print $2}') / 3" | bc)M \
	log_path=/var/log/mail.log

# The inotify `max_user_instances` default is 128, which constrains
# the total number of watched (IMAP IDLE push) folders by open connections.
# See http://www.dovecot.org/pipermail/dovecot/2013-March/088834.html.
# A reboot is required for this to take effect (which we don't do as
# as a part of setup). Test with `cat /proc/sys/fs/inotify/max_user_instances`.
tools/editconf.py /etc/sysctl.conf \
	fs.inotify.max_user_instances=1024

# Set the location where we'll store user mailboxes. '%d' is the domain name and '%n' is the
# username part of the user's email address. We'll ensure that no bad domains or email addresses
# are created within the management daemon.
tools/editconf.py /etc/dovecot/conf.d/10-mail.conf \
	mail_location=maildir:$STORAGE_ROOT/mail/mailboxes/%d/%n \
	mail_privileged_group=mail \
	first_valid_uid=0

# Create, subscribe, and mark as special folders: INBOX, Drafts, Sent, Trash, Spam and Archive.
cp conf/dovecot-mailboxes.conf /etc/dovecot/conf.d/15-mailboxes.conf

# ### IMAP/POP

# Require that passwords are sent over SSL only, and allow the usual IMAP authentication mechanisms.
# The LOGIN mechanism is supposedly for Microsoft products like Outlook to do SMTP login (I guess
# since we're using Dovecot to handle SMTP authentication?).
tools/editconf.py /etc/dovecot/conf.d/10-auth.conf \
	disable_plaintext_auth=yes \
	"auth_mechanisms=plain login"

# Enable SSL, specify the location of the SSL certificate and private key files.
# Use Mozilla's "Intermediate" recommendations at https://ssl-config.mozilla.org/#server=dovecot&server-version=2.2.33&config=intermediate&openssl-version=1.1.1,
# except that the current version of Dovecot does not have a TLSv1.3 setting, so we only use TLSv1.2.
tools/editconf.py /etc/dovecot/conf.d/10-ssl.conf \
	ssl=required \
	"ssl_cert=<$STORAGE_ROOT/ssl/ssl_certificate.pem" \
	"ssl_key=<$STORAGE_ROOT/ssl/ssl_private_key.pem" \
	"ssl_min_protocol=TLSv1.2" \
	"ssl_cipher_list=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384" \
	"ssl_prefer_server_ciphers=no" \
	"ssl_dh_parameters_length=2048" \
	"ssl_dh=<$STORAGE_ROOT/ssl/dh2048.pem"

# Disable in-the-clear IMAP/POP because there is no reason for a user to transmit
# login credentials outside of an encrypted connection. Only the over-TLS versions
# are made available (IMAPS on port 993; POP3S on port 995).
sed -i "s/#port = 143/port = 0/" /etc/dovecot/conf.d/10-master.conf
sed -i "s/#port = 110/port = 0/" /etc/dovecot/conf.d/10-master.conf

# Make IMAP IDLE slightly more efficient. By default, Dovecot says "still here"
# every two minutes. With K-9 mail, the bandwidth and battery usage due to
# this are minimal. But for good measure, let's go to 4 minutes to halve the
# bandwidth and number of times the device's networking might be woken up.
# The risk is that if the connection is silent for too long it might be reset
# by a peer. See [#129](https://github.com/mail-in-a-box/mailinabox/issues/129)
# and [How bad is IMAP IDLE](http://razor.occams.info/blog/2014/08/09/how-bad-is-imap-idle/).
tools/editconf.py /etc/dovecot/conf.d/20-imap.conf \
	imap_idle_notify_interval="4 mins"

# Set POP3 UIDL.
# UIDLs are used by POP3 clients to keep track of what messages they've downloaded.
# For new POP3 servers, the easiest way to set up UIDLs is to use IMAP's UIDVALIDITY
# and UID values, the default in Dovecot.
tools/editconf.py /etc/dovecot/conf.d/20-pop3.conf \
	pop3_uidl_format="%08Xu%08Xv"

# ### LDA (LMTP)

# Enable Dovecot's LDA service with the LMTP protocol. It will listen
# on port 10026, and Spamassassin will be configured to pass mail there.
#
# The disabled unix socket listener is normally how Postfix and Dovecot
# would communicate (see the Postfix setup script for the corresponding
# setting also commented out).
#
# Also increase the number of allowed IMAP connections per mailbox because
# we all have so many devices lately.
cat > /etc/dovecot/conf.d/99-local.conf << EOF;
service lmtp {
  #unix_listener /var/spool/postfix/private/dovecot-lmtp {
  #  user = postfix
  #  group = postfix
  #}
  inet_listener lmtp {
    address = 127.0.0.1
    port = 10026
  }
}

# Enable imap-login on localhost to allow the user_external plugin
# for Nextcloud to do imap authentication. (See #1577)
service imap-login {
  inet_listener imap {
    address = 127.0.0.1
    port = 143
  }
}
protocol imap {
  mail_max_userip_connections = 40
}
EOF


# ### Sieve

# Enable the Dovecot sieve plugin which let's users run scripts that process
# mail as it comes in.
sed -i "s/#mail_plugins = .*/mail_plugins = \$mail_plugins sieve/" /etc/dovecot/conf.d/20-lmtp.conf

# Configure sieve. We'll create a global script that moves mail marked
# as spam by Spamassassin into the user's Spam folder.
#
# * `sieve_before`: The path to our global sieve which handles moving spam to the Spam folder.
#
# * `sieve_before2`: The path to our global sieve directory for sieve which can contain .sieve files
# to run globally for every user before their own sieve files run.
#
# * `sieve_after`: The path to our global sieve directory which can contain .sieve files
# to run globally for every user after their own sieve files run.
#
# * `sieve`: The path to the user's main active script. ManageSieve will create a symbolic
# link here to the actual sieve script. It should not be in the mailbox directory
# (because then it might appear as a folder) and it should not be in the sieve_dir
# (because then I suppose it might appear to the user as one of their scripts).
# * `sieve_dir`: Directory for :personal include scripts for the include extension. This
# is also where the ManageSieve service stores the user's scripts.
cat > /etc/dovecot/conf.d/99-local-sieve.conf << EOF;
plugin {
  sieve_before = /etc/dovecot/sieve-spam.sieve
  sieve_before2 = $STORAGE_ROOT/mail/sieve/global_before
  sieve_after = $STORAGE_ROOT/mail/sieve/global_after
  sieve = $STORAGE_ROOT/mail/sieve/%d/%n.sieve
  sieve_dir = $STORAGE_ROOT/mail/sieve/%d/%n
  sieve_redirect_envelope_from = recipient
}
EOF

# Copy the global sieve script into where we've told Dovecot to look for it. Then
# compile it. Global scripts must be compiled now because Dovecot won't have
# permission later.
cp conf/sieve-spam.txt /etc/dovecot/sieve-spam.sieve
sievec /etc/dovecot/sieve-spam.sieve

# PERMISSIONS

# Ensure configuration files are owned by dovecot and not world readable.
chown -R mail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot

# Ensure mailbox files have a directory that exists and are owned by the mail user.
mkdir -p $STORAGE_ROOT/mail/mailboxes
chown -R mail.mail $STORAGE_ROOT/mail/mailboxes

# Same for the sieve scripts.
mkdir -p $STORAGE_ROOT/mail/sieve
mkdir -p $STORAGE_ROOT/mail/sieve/global_before
mkdir -p $STORAGE_ROOT/mail/sieve/global_after
chown -R mail.mail $STORAGE_ROOT/mail/sieve




######################################################################
#
# mail-users.sh
#
echo MIAC GENERIC mail-users.sh

# Create an empty database if it doesn't yet exist.
if [ ! -f $db_path ]; then
	echo Creating new user database: $db_path;
	echo "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, extra, privileges TEXT NOT NULL DEFAULT '');" | sqlite3 $db_path;
	echo "CREATE TABLE aliases (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL UNIQUE, destination TEXT NOT NULL, permitted_senders TEXT);" | sqlite3 $db_path;
	echo "CREATE TABLE mfa (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, secret TEXT NOT NULL, mru_token TEXT, label TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);" | sqlite3 $db_path;
	echo "CREATE TABLE auto_aliases (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL UNIQUE, destination TEXT NOT NULL, permitted_senders TEXT);" | sqlite3 $db_path;
fi

# ### User Authentication

# Have Dovecot query our database, and not system users, for authentication.
sed -i "s/#*\(\!include auth-system.conf.ext\)/#\1/"  /etc/dovecot/conf.d/10-auth.conf
sed -i "s/#\(\!include auth-sql.conf.ext\)/\1/"  /etc/dovecot/conf.d/10-auth.conf

# Specify how the database is to be queried for user authentication (passdb)
# and where user mailboxes are stored (userdb).
cat > /etc/dovecot/conf.d/auth-sql.conf.ext << EOF;
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
EOF

# Configure the SQL to query for a user's metadata and password.
cat > /etc/dovecot/dovecot-sql.conf.ext << EOF;
driver = sqlite
connect = $db_path
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM users WHERE email='%u';
user_query = SELECT email AS user, "mail" as uid, "mail" as gid, "$STORAGE_ROOT/mail/mailboxes/%d/%n" as home FROM users WHERE email='%u';
iterate_query = SELECT email AS user FROM users;
EOF
chmod 0600 /etc/dovecot/dovecot-sql.conf.ext # per Dovecot instructions

# Have Dovecot provide an authorization service that Postfix can access & use.
cat > /etc/dovecot/conf.d/99-local-auth.conf << EOF;
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
}
EOF

# And have Postfix use that service. We *disable* it here
# so that authentication is not permitted on port 25 (which
# does not run DKIM on relayed mail, so outbound mail isn't
# correct, see #830), but we enable it specifically for the
# submission port.
tools/editconf.py /etc/postfix/main.cf \
	smtpd_sasl_type=dovecot \
	smtpd_sasl_path=private/auth \
	smtpd_sasl_auth_enable=no

# ### Sender Validation

# We use Postfix's reject_authenticated_sender_login_mismatch filter to
# prevent intra-domain spoofing by logged in but untrusted users in outbound
# email. In all outbound mail (the sender has authenticated), the MAIL FROM
# address (aka envelope or return path address) must be "owned" by the user
# who authenticated. An SQL query will find who are the owners of any given
# address.
tools/editconf.py /etc/postfix/main.cf \
	smtpd_sender_login_maps=sqlite:/etc/postfix/sender-login-maps.cf

# Postfix will query the exact address first, where the priority will be alias
# records first, then user records. If there are no matches for the exact
# address, then Postfix will query just the domain part, which we call
# catch-alls and domain aliases. A NULL permitted_senders column means to
# take the value from the destination column.
cat > /etc/postfix/sender-login-maps.cf << EOF;
dbpath=$db_path
query = SELECT permitted_senders FROM (SELECT permitted_senders, 0 AS priority FROM aliases WHERE source='%s' AND permitted_senders IS NOT NULL UNION SELECT destination AS permitted_senders, 1 AS priority FROM aliases WHERE source='%s' AND permitted_senders IS NULL UNION SELECT email as permitted_senders, 2 AS priority FROM users WHERE email='%s') ORDER BY priority LIMIT 1;
EOF

# ### Destination Validation

# Use a Sqlite3 database to check whether a destination email address exists,
# and to perform any email alias rewrites in Postfix. Additionally, we disable
# SMTPUTF8 because Dovecot's LMTP server that delivers mail to inboxes does
# not support it, and if a message is received with the SMTPUTF8 flag it will
# bounce.
tools/editconf.py /etc/postfix/main.cf \
	smtputf8_enable=no \
	virtual_mailbox_domains=sqlite:/etc/postfix/virtual-mailbox-domains.cf \
	virtual_mailbox_maps=sqlite:/etc/postfix/virtual-mailbox-maps.cf \
	virtual_alias_maps=sqlite:/etc/postfix/virtual-alias-maps.cf \
	local_recipient_maps=\$virtual_mailbox_maps

# SQL statement to check if we handle incoming mail for a domain, either for users or aliases.
cat > /etc/postfix/virtual-mailbox-domains.cf << EOF;
dbpath=$db_path
query = SELECT 1 FROM users WHERE email LIKE '%%@%s' UNION SELECT 1 FROM aliases WHERE source LIKE '%%@%s' UNION SELECT 1 FROM auto_aliases WHERE source LIKE '%%@%s'
EOF

# SQL statement to check if we handle incoming mail for a user.
cat > /etc/postfix/virtual-mailbox-maps.cf << EOF;
dbpath=$db_path
query = SELECT 1 FROM users WHERE email='%s'
EOF

# SQL statement to rewrite an email address if an alias is present.
#
# Postfix makes multiple queries for each incoming mail. It first
# queries the whole email address, then just the user part in certain
# locally-directed cases (but we don't use this), then just `@`+the
# domain part. The first query that returns something wins. See
# http://www.postfix.org/virtual.5.html.
#
# virtual-alias-maps has precedence over virtual-mailbox-maps, but
# we don't want catch-alls and domain aliases to catch mail for users
# that have been defined on those domains. To fix this, we not only
# query the aliases table but also the users table when resolving
# aliases, i.e. we turn users into aliases from themselves to
# themselves. That means users will match in postfix's first query
# before postfix gets to the third query for catch-alls/domain alises.
#
# If there is both an alias and a user for the same address either
# might be returned by the UNION, so the whole query is wrapped in
# another select that prioritizes the alias definition to preserve
# postfix's preference for aliases for whole email addresses.
#
# Since we might have alias records with an empty destination because
# it might have just permitted_senders, skip any records with an
# empty destination here so that other lower priority rules might match.
cat > /etc/postfix/virtual-alias-maps.cf << EOF;
dbpath=$db_path
query = SELECT destination from (SELECT destination, 0 as priority FROM aliases WHERE source='%s' AND destination<>'' UNION SELECT email as destination, 1 as priority FROM users WHERE email='%s' UNION SELECT destination, 2 as priority FROM auto_aliases WHERE source='%s' AND destination<>'') ORDER BY priority LIMIT 1;
EOF



######################################################################
#
# dkim.sh
#
echo MIAC GENERIC dkim.sh

# Make sure configuration directories exist.
mkdir -p /etc/opendkim;
mkdir -p $STORAGE_ROOT/mail/dkim

# Used in InternalHosts and ExternalIgnoreList configuration directives.
# Not quite sure why.
echo "127.0.0.1" > /etc/opendkim/TrustedHosts

# We need to at least create these files, since we reference them later.
# Otherwise, opendkim startup will fail
touch /etc/opendkim/KeyTable
touch /etc/opendkim/SigningTable

if grep -q "ExternalIgnoreList" /etc/opendkim.conf; then
	true # already done #NODOC
else
	# Add various configuration options to the end of `opendkim.conf`.
	cat >> /etc/opendkim.conf << EOF;
Canonicalization		relaxed/simple
MinimumKeyBits          1024
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Socket                  inet:8891@127.0.0.1
RequireSafeKeys         false
EOF
fi


tools/editconf.py /etc/opendmarc.conf -s \
	"Syslog=true" \
	"Socket=inet:8893@[127.0.0.1]" \
	"FailureReports=true"

# SPFIgnoreResults causes the filter to ignore any SPF results in the header
# of the message. This is useful if you want the filter to perfrom SPF checks
# itself, or because you don't trust the arriving header. This added header is
# used by spamassassin to evaluate the mail for spamminess.

tools/editconf.py /etc/opendmarc.conf -s \
        "SPFIgnoreResults=true"

# SPFSelfValidate causes the filter to perform a fallback SPF check itself
# when it can find no SPF results in the message header. If SPFIgnoreResults
# is also set, it never looks for SPF results in headers and always performs
# the SPF check itself when this is set. This added header is used by
# spamassassin to evaluate the mail for spamminess.

tools/editconf.py /etc/opendmarc.conf -s \
        "SPFSelfValidate=true"

# Enables generation of failure reports for sending domains that publish a
# "none" policy.

tools/editconf.py /etc/opendmarc.conf -s \
        "FailureReportsOnNone=true"

# AlwaysAddARHeader Adds an "Authentication-Results:" header field even to
# unsigned messages from domains with no "signs all" policy. The reported DKIM
# result will be  "none" in such cases. Normally unsigned mail from non-strict
# domains does not cause the results header field to be added. This added header
# is used by spamassassin to evaluate the mail for spamminess.

tools/editconf.py /etc/opendkim.conf -s \
        "AlwaysAddARHeader=true"

# Add OpenDKIM and OpenDMARC as milters to postfix, which is how OpenDKIM
# intercepts outgoing mail to perform the signing (by adding a mail header)
# and how they both intercept incoming mail to add Authentication-Results
# headers. The order possibly/probably matters: OpenDMARC relies on the
# OpenDKIM Authentication-Results header already being present.
#
# Be careful. If we add other milters later, this needs to be concatenated
# on the smtpd_milters line.
#
# The OpenDMARC milter is skipped in the SMTP submission listener by
# configuring smtpd_milters there to only list the OpenDKIM milter
# (see mail-postfix.sh).
tools/editconf.py /etc/postfix/main.cf \
	"smtpd_milters=inet:127.0.0.1:8891 inet:127.0.0.1:8893"\
	non_smtpd_milters=\$smtpd_milters \
	milter_default_action=accept



######################################################################
#
# spamassassin.sh
#
echo MIAC GENERIC spamassassin.sh

# Allow spamassassin to download new rules.
tools/editconf.py /etc/default/spamassassin \
	CRON=1

# Configure pyzor, which is a client to a live database of hashes of
# spam emails. Set the pyzor configuration directory to something sane.
# The default is ~/.pyzor. We used to use that, so we'll kill that old
# directory. Then write the public pyzor server to its servers file.
# That will prevent an automatic download on first use, and also means
# we can skip 'pyzor discover', both of which are currently broken by
# something happening on Sourceforge (#496).
rm -rf ~/.pyzor
tools/editconf.py /etc/spamassassin/local.cf -s \
	pyzor_options="--homedir /etc/spamassassin/pyzor"
mkdir -p /etc/spamassassin/pyzor
echo "public.pyzor.org:24441" > /etc/spamassassin/pyzor/servers
# check with: pyzor --homedir /etc/mail/spamassassin/pyzor ping

# Configure spampd:
# * Pass messages on to docevot on port 10026. This is actually the default setting but we don't
#   want to lose track of it. (We've configured Dovecot to listen on this port elsewhere.)
# * Increase the maximum message size of scanned messages from the default of 64KB to 500KB, which
#   is Spamassassin (spamc)'s own default. Specified in KBytes.
# * Disable localmode so Pyzor, DKIM and DNS checks can be used.
tools/editconf.py /etc/default/spampd \
	DESTPORT=10026 \
	ADDOPTS="\"--maxsize=2000\"" \
	LOCALONLY=0

# Spamassassin normally wraps spam as an attachment inside a fresh
# email with a report about the message. This also protects the user
# from accidentally openening a message with embedded malware.
#
# It's nice to see what rules caused the message to be marked as spam,
# but it's also annoying to get to the original message when it is an
# attachment, modern mail clients are safer now and don't load remote
# content or execute scripts, and it is probably confusing to most users.
#
# Tell Spamassassin not to modify the original message except for adding
# the X-Spam-Status & X-Spam-Score mail headers and related headers.
tools/editconf.py /etc/spamassassin/local.cf -s \
	report_safe=0 \
	"add_header all Report"=_REPORT_ \
	"add_header all Score"=_SCORE_


# Bayesean learning
# -----------------
#
# Spamassassin can learn from mail marked as spam or ham, but it needs to be
# configured. We'll store the learning data in our storage area.
#
# These files must be:
#
# * Writable by sa-learn-pipe script below, which run as the 'mail' user, for manual tagging of mail as spam/ham.
# * Readable by the spampd process ('spampd' user) during mail filtering.
# * Writable by the debian-spamd user, which runs /etc/cron.daily/spamassassin.
#
# We'll have these files owned by spampd and grant access to the other two processes.
#
# Spamassassin will change the access rights back to the defaults, so we must also configure
# the filemode in the config file.

tools/editconf.py /etc/spamassassin/local.cf -s \
	bayes_path=$STORAGE_ROOT/mail/spamassassin/bayes \
	bayes_file_mode=0666

mkdir -p $STORAGE_ROOT/mail/spamassassin
chown -R spampd:spampd $STORAGE_ROOT/mail/spamassassin

# To mark mail as spam or ham, just drag it in or out of the Spam folder. We'll
# use the Dovecot antispam plugin to detect the message move operation and execute
# a shell script that invokes learning.

# Enable the Dovecot antispam plugin.
# (Be careful if we use multiple plugins later.) #NODOC
sed -i "s/#mail_plugins = .*/mail_plugins = \$mail_plugins antispam/" /etc/dovecot/conf.d/20-imap.conf
sed -i "s/#mail_plugins = .*/mail_plugins = \$mail_plugins antispam/" /etc/dovecot/conf.d/20-pop3.conf

# Configure the antispam plugin to call sa-learn-pipe.sh.
cat > /etc/dovecot/conf.d/99-local-spampd.conf << EOF;
plugin {
    antispam_backend = pipe
    antispam_spam_pattern_ignorecase = SPAM
    antispam_trash_pattern_ignorecase = trash;Deleted *
    antispam_allow_append_to_spam = yes
    antispam_pipe_program_spam_args = /usr/local/bin/sa-learn-pipe.sh;--spam
    antispam_pipe_program_notspam_args = /usr/local/bin/sa-learn-pipe.sh;--ham
    antispam_pipe_program = /bin/bash
}
EOF

# Have Dovecot run its mail process with a supplementary group (the spampd group)
# so that it can access the learning files.

tools/editconf.py /etc/dovecot/conf.d/10-mail.conf \
	mail_access_groups=spampd

# Here's the script that the antispam plugin executes. It spools the message into
# a temporary file and then runs sa-learn on it.
# from http://wiki2.dovecot.org/Plugins/Antispam
rm -f /usr/bin/sa-learn-pipe.sh # legacy location #NODOC
cat > /usr/local/bin/sa-learn-pipe.sh << EOF;
cat<&0 >> /tmp/sendmail-msg-\$\$.txt
/usr/bin/sa-learn \$* /tmp/sendmail-msg-\$\$.txt > /dev/null
rm -f /tmp/sendmail-msg-\$\$.txt
exit 0
EOF
chmod a+x /usr/local/bin/sa-learn-pipe.sh

# Create empty bayes training data (if it doesn't exist). Once the files exist,
# ensure they are group-writable so that the Dovecot process has access.
sudo -u spampd /usr/bin/sa-learn --sync 2>/dev/null
chmod -R 660 $STORAGE_ROOT/mail/spamassassin
chmod 770 $STORAGE_ROOT/mail/spamassassin



######################################################################
#
# web.sh
#
echo MIAC GENERIC web.sh

# Copy in a nginx configuration file for common and best-practices
# SSL settings from @konklone. Replace STORAGE_ROOT so it can find
# the DH params.
rm -f /etc/nginx/nginx-ssl.conf # we used to put it here
sed "s#STORAGE_ROOT#$STORAGE_ROOT#" \
	conf/nginx-ssl.conf > /etc/nginx/conf.d/ssl.conf

# Fix some nginx defaults.
#
# The server_names_hash_bucket_size seems to prevent long domain names!
# The default, according to nginx's docs, depends on "the size of the
# processor’s cache line." It could be as low as 32. We fixed it at
# 64 in 2014 to accommodate a long domain name (20 characters?). But
# even at 64, a 58-character domain name won't work (#93), so now
# we're going up to 128.
#
# Drop TLSv1.0, TLSv1.1, following the Mozilla "Intermediate" recommendations
# at https://ssl-config.mozilla.org/#server=nginx&server-version=1.17.0&config=intermediate&openssl-version=1.1.1.
tools/editconf.py /etc/nginx/nginx.conf -s \
	server_names_hash_bucket_size="128;" \
	ssl_protocols="TLSv1.2 TLSv1.3;"

# Tell PHP not to expose its version number in the X-Powered-By header.
tools/editconf.py /etc/php/$PHP_VER/fpm/php.ini -c ';' \
	expose_php=Off

# Set PHPs default charset to UTF-8, since we use it. See #367.
tools/editconf.py /etc/php/$PHP_VER/fpm/php.ini -c ';' \
        default_charset="UTF-8"

# Configure the path environment for php-fpm
tools/editconf.py /etc/php/$PHP_VER/fpm/pool.d/www.conf -c ';' \
	env[PATH]=/usr/local/bin:/usr/bin:/bin \

# Configure php-fpm based on the amount of memory the machine has
# This is based on the nextcloud manual for performance tuning: https://docs.nextcloud.com/server/17/admin_manual/installation/server_tuning.html
# Some synchronisation issues can occur when many people access the site at once.
# The pm=ondemand setting is used for memory constrained machines < 2GB, this is copied over from PR: 1216
TOTAL_PHYSICAL_MEM=$(head -n 1 /proc/meminfo | awk '{print $2}' || /bin/true)
if [ $TOTAL_PHYSICAL_MEM -lt 1000000 ]
then
        tools/editconf.py /etc/php/$PHP_VER/fpm/pool.d/www.conf -c ';' \
                pm=ondemand \
                pm.max_children=8 \
                pm.start_servers=2 \
                pm.min_spare_servers=1 \
                pm.max_spare_servers=3
elif [ $TOTAL_PHYSICAL_MEM -lt 2000000 ]
then
        tools/editconf.py /etc/php/$PHP_VER/fpm/pool.d/www.conf -c ';' \
                pm=ondemand \
                pm.max_children=16 \
                pm.start_servers=4 \
                pm.min_spare_servers=1 \
                pm.max_spare_servers=6
elif [ $TOTAL_PHYSICAL_MEM -lt 3000000 ]
then
        tools/editconf.py /etc/php/$PHP_VER/fpm/pool.d/www.conf -c ';' \
                pm=dynamic \
                pm.max_children=60 \
                pm.start_servers=6 \
                pm.min_spare_servers=3 \
                pm.max_spare_servers=9
else
        tools/editconf.py /etc/php/$PHP_VER/fpm/pool.d/www.conf -c ';' \
                pm=dynamic \
                pm.max_children=120 \
                pm.start_servers=12 \
                pm.min_spare_servers=6 \
                pm.max_spare_servers=18
fi

# Other nginx settings will be configured by the management service
# since it depends on what domains we're serving, which we don't know
# until mail accounts have been created.

# Create the iOS/OS X Mobile Configuration file which is exposed via the
# nginx configuration at /mailinabox-mobileconfig.
mkdir -p /var/lib/mailinabox
chmod a+rx /var/lib/mailinabox


# MIAC TODO: resolve stateful/idempotent semantics of the directory mv

# make a default homepage
if [ -d $STORAGE_ROOT/www/static ]; then mv $STORAGE_ROOT/www/static $STORAGE_ROOT/www/default; fi # migration #NODOC
mkdir -p $STORAGE_ROOT/www/default
if [ ! -f $STORAGE_ROOT/www/default/index.html ]; then
	cp conf/www_default.html $STORAGE_ROOT/www/default/index.html
fi

chown -R $STORAGE_USER $STORAGE_ROOT/www



######################################################################
#
# webmail.sh
#
echo MIAC GENERIC webmail.sh

# Create writable directories.
mkdir -p /var/log/roundcubemail /var/tmp/roundcubemail $STORAGE_ROOT/mail/roundcube
chown -R www-data.www-data /var/log/roundcubemail /var/tmp/roundcubemail $STORAGE_ROOT/mail/roundcube

# Ensure the log file monitored by fail2ban exists, or else fail2ban can't start.
sudo -u www-data touch /var/log/roundcubemail/errors.log

# Password changing plugin settings
# The config comes empty by default, so we need the settings
# we're not planning to change in config.inc.dist...
cp ${RCM_PLUGIN_DIR}/password/config.inc.php.dist \
	${RCM_PLUGIN_DIR}/password/config.inc.php

tools/editconf.py ${RCM_PLUGIN_DIR}/password/config.inc.php \
	"\$config['password_minimum_length']=8;" \
	"\$config['password_db_dsn']='sqlite:///$STORAGE_ROOT/mail/users.sqlite';" \
	"\$config['password_query']='UPDATE users SET password=%D WHERE email=%u';" \
	"\$config['password_dovecotpw']='/usr/bin/doveadm pw';" \
	"\$config['password_dovecotpw_method']='SHA512-CRYPT';" \
	"\$config['password_dovecotpw_with_method']=true;"

# so PHP can use doveadm, for the password changing plugin
usermod -a -G dovecot www-data

# set permissions so that PHP can use users.sqlite
# could use dovecot instead of www-data, but not sure it matters
chown root.www-data $STORAGE_ROOT/mail
chmod 775 $STORAGE_ROOT/mail
chown root.www-data $STORAGE_ROOT/mail/users.sqlite
chmod 664 $STORAGE_ROOT/mail/users.sqlite

# Fix Carddav permissions:
chown -f -R root.www-data ${RCM_PLUGIN_DIR}/carddav
# root.www-data need all permissions, others only read
chmod -R 774 ${RCM_PLUGIN_DIR}/carddav



######################################################################
#
# nextcloud.sh
#
echo MIAC GENERIC nextcloud.sh

# Enable APC before Nextcloud tools are run.
tools/editconf.py /etc/php/$PHP_VER/mods-available/apcu.ini -c ';' \
	apc.enabled=1 \
	apc.enable_cli=1


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







######################################################################
#
# zpush.sh
#
echo MIAC GENERIC zpush.sh

# Configure default config.
sed -i "s^define('TIMEZONE', .*^define('TIMEZONE', '$(cat /etc/timezone)');^" /usr/local/lib/z-push/config.php
sed -i "s/define('BACKEND_PROVIDER', .*/define('BACKEND_PROVIDER', 'BackendCombined');/" /usr/local/lib/z-push/config.php
sed -i "s/define('USE_FULLEMAIL_FOR_LOGIN', .*/define('USE_FULLEMAIL_FOR_LOGIN', true);/" /usr/local/lib/z-push/config.php
sed -i "s/define('LOG_MEMORY_PROFILER', .*/define('LOG_MEMORY_PROFILER', false);/" /usr/local/lib/z-push/config.php
sed -i "s/define('BUG68532FIXED', .*/define('BUG68532FIXED', false);/" /usr/local/lib/z-push/config.php
sed -i "s/define('LOGLEVEL', .*/define('LOGLEVEL', LOGLEVEL_ERROR);/" /usr/local/lib/z-push/config.php

# Configure BACKEND
rm -f /usr/local/lib/z-push/backend/combined/config.php
cp conf/zpush/backend_combined.php /usr/local/lib/z-push/backend/combined/config.php

# Configure IMAP
rm -f /usr/local/lib/z-push/backend/imap/config.php
cp conf/zpush/backend_imap.php /usr/local/lib/z-push/backend/imap/config.php
sed -i "s%STORAGE_ROOT%$STORAGE_ROOT%" /usr/local/lib/z-push/backend/imap/config.php

# Configure CardDav
rm -f /usr/local/lib/z-push/backend/carddav/config.php
cp conf/zpush/backend_carddav.php /usr/local/lib/z-push/backend/carddav/config.php

# Configure CalDav
rm -f /usr/local/lib/z-push/backend/caldav/config.php
cp conf/zpush/backend_caldav.php /usr/local/lib/z-push/backend/caldav/config.php

# Configure Autodiscover
rm -f /usr/local/lib/z-push/autodiscover/config.php
cp conf/zpush/autodiscover_config.php /usr/local/lib/z-push/autodiscover/config.php


# Some directories it will use.

mkdir -p /var/log/z-push
mkdir -p /var/lib/z-push
chmod 750 /var/log/z-push
chmod 750 /var/lib/z-push
chown www-data:www-data /var/log/z-push
chown www-data:www-data /var/lib/z-push

# Add log rotation

cat > /etc/logrotate.d/z-push <<EOF;
/var/log/z-push/*.log {
	weekly
	missingok
	rotate 52
	compress
	delaycompress
	notifempty
}
EOF



######################################################################
#
# management.sh
#
echo MIAC GENERIC management.sh

# Create an init script to start the management daemon and keep it
# running after a reboot.
# Set a long timeout since some commands take a while to run, matching
# the timeout we set for PHP (fastcgi_read_timeout in the nginx confs).
# Note: Authentication currently breaks with more than 1 gunicorn worker.
cat > $inst_dir/start <<EOF;
#!/bin/bash
# Set character encoding flags to ensure that any non-ASCII don't cause problems.
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_TYPE=en_US.UTF-8

mkdir -p /var/lib/mailinabox
tr -cd '[:xdigit:]' < /dev/urandom | head -c 32 > /var/lib/mailinabox/api.key
chmod 640 /var/lib/mailinabox/api.key

source $venv/bin/activate
export PYTHONPATH=$(pwd)/management
exec gunicorn -b localhost:10222 -w 1 --timeout 630 wsgi:app
EOF
chmod +x $inst_dir/start
cp --remove-destination conf/mailinabox.service /lib/systemd/system/mailinabox.service # target was previously a symlink so remove it first



######################################################################
#
# letsencrypt.sh
#
echo MIAC GENERIC letsencrypt.sh

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



######################################################################
#
# munin.sh
#
echo MIAC GENERIC munin.sh

# The Debian installer touches these files and chowns them to www-data:adm for use with spawn-fcgi
chown munin /var/log/munin/munin-cgi-html.log
chown munin /var/log/munin/munin-cgi-graph.log


# Create a 'state' directory. Not sure why we need to do this manually.
mkdir -p /var/lib/munin-node/plugin-state/

# Create a systemd service for munin.
ln -sf $(pwd)/management/munin_start.sh /usr/local/lib/mailinabox/munin_start.sh
chmod 0744 /usr/local/lib/mailinabox/munin_start.sh
cp --remove-destination conf/munin.service /lib/systemd/system/munin.service # target was previously a symlink so remove first

# MIAC not sure if these steps are necessary
# Ensure this directory exists regardless of whether services will be run that create it
mkdir -p /var/run/munin
chown munin:munin /var/run/munin


# ensure success code when this script is sourced
/bin/true

