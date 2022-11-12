#!/bin/bash
# This is the entry point for configuring the system.
#####################################################


# Check system setup: Are we running as root on Ubuntu 18.04 on a
# machine with enough memory? Is /tmp mounted with exec.
# If not, this shows an error and exits.
source setup/preflight.sh

source setup/functions.sh # load our functions
source setup/locale.sh # export locale env vars

# Create /usr/local/bin/mailinabox early
source setup/mailinabox-bin.sh

# Migrate existing installation, capture DEFAULT_* config
source setup/migrate.sh

# Ask the user for the PRIMARY_HOSTNAME, PUBLIC_IP, and PUBLIC_IPV6,
# if values have not already been set in environment variables. When running
# non-interactively, be sure to set values for all! Also sets STORAGE_USER and
# STORAGE_ROOT.
source setup/questions.sh

# Run some network checks to make sure setup on this machine makes sense.
source setup/network-checks.sh

# Crete global options in /etc/mailinabox.conf, generic or specific
source setup/mailinabox-conf.sh

# Create the STORAGE_ROOT, and perhaps STORAGE_USER
source setup/user-storage.sh

# Services configuration.
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
source setup/letsencrypt.sh  # register a certbot account
source setup/munin.sh

source setup/update-state.sh

# If there aren't any mail users yet, create one.
source setup/firstuser.sh

source setup/running-banner.sh
