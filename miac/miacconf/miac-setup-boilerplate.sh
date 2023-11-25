# MIAC: BOILERPLATE

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# system.sh
#
echo MIAC BOILERPLATE system.sh

source /etc/mailinabox.conf
source setup/functions.sh # load our functions
source setup/locale.sh # export locale env vars



######################################################################
#
# ssl.sh
#
echo MIAC BOILERPLATE ssl.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# dns.sh
#
echo MIAC BOILERPLATE dns.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# mail-postfix.sh
#
echo MIAC BOILERPLATE mail-postfix.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# mail-dovecot.sh
#
echo MIAC BOILERPLATE mail-dovecot.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# mail-users.sh
#
echo MIAC BOILERPLATE mail-users.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# dkim.sh
#
echo MIAC BOILERPLATE dkim.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# spamassassin.sh
#
echo MIAC BOILERPLATE spamassassin.sh

source /etc/mailinabox.conf # get global vars
source setup/functions.sh # load our functions



######################################################################
#
# web.sh
#
echo MIAC BOILERPLATE web.sh

#!/bin/bash
# HTTP: Turn on a web server serving static files
#################################################

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# webmail.sh
#
echo MIAC BOILERPLATE webmail.sh

#!/bin/bash
# Webmail with Roundcube
# ----------------------

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# nextcloud.sh
#
echo MIAC BOILERPLATE nextcloud.sh

#!/bin/bash
# Nextcloud
##########################

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# zpush.sh
#
echo MIAC BOILERPLATE zpush.sh

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars



######################################################################
#
# management.sh
#
echo MIAC BOILERPLATE management.sh

#!/bin/bash

source setup/functions.sh
source /etc/mailinabox.conf # load global vars



######################################################################
#
# munin.sh
#
echo MIAC BOILERPLATE munin.sh

#!/bin/bash
# Munin: resource monitoring tool
#################################################

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars


# ensure success code when this script is sourced
/bin/true

