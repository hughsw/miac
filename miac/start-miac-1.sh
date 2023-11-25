#!/bin/bash

# Set strict, Load functions
source setup/functions.sh 
# Export some locale envs
source setup/locale.sh


# continue

# This is the entry point for configuring the system.
#####################################################

# Start service configuration.
source setup/system.sh
source setup/ssl.sh
#source setup/dns.sh
source setup/mail-postfix.sh
source setup/mail-dovecot.sh
source setup/mail-users.sh
source setup/dkim.sh
source setup/spamassassin.sh
printenv
source setup/web.sh

true
