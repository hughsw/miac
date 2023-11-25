#!/bin/bash

set -euo pipefail

set -x

# Changes to mail-in-a-box
cd /home/miac/mailinabox

# don't do apt-get install
sed -i \
  -e 's|\bapt_get_quiet install\b|echo MIAC skipping apt-get install:|' \
  setup/functions.sh
#  -e 's|\bapt_install\b|echo skipping apt_install:|' \


# TODO: revisit memory concerns...
sed -i \
  -e 's|\bsource setup/preflight.sh\b|echo MIAC skipping source setup/preflight.sh|' \
  setup/preflight.sh

sed -i \
  -e 's|^restart_service fail2ban$|restart_service fail2ban\nrestart_service nsd  # MIAC|' \
  -e 's|Fingerprint=//"|Fingerprint=//i"|' \
  setup/start.sh
#  -e 's|^restart_service fail2ban$|restart_service fail2ban\nrestart_service nsd\nnsd-control reload|' \

sed -i \
  -e 's|^rm -f /etc/resolv.conf$|echo > /etc/resolv.conf  # MIAC|' \
  -e 's|^pollinate  -q -r|echo MIAC skipping pollinate  -q -r|' \
  -e 's|\bapt_install bind9\b|apt_get_quiet install bind9  # MIAC|' \
  -e 's|\bhide_output add-apt-repository\b|echo MIAC skipping add-apt-repository:|' \
  setup/system.sh

# intervene to ensure /var/log/nsd.log is set up...
sed -i \
  -e 's|^apt_install nsd ldnsutils openssh-client$|apt_get_quiet install nsd ldnsutils openssh-client \&\& touch /var/log/nsd.log \&\& chown nsd:nsd /var/log/nsd.log  # MIAC|' \
  setup/dns.sh

#  -e 's|^apt_install nsd ldnsutils openssh-client$|apt_install nsd ldnsutils openssh-client \&\& touch /var/log/nsd.log \&\& chown nsd:nsd /var/log/nsd.log|' \


# sed -i \
#   -e 's|en_US\.UTF-8|C.UTF-8|ig' \
#   setup/management.sh \

#   -e 's|^apt_install nsd ldnsutils openssh-client$|apt_install nsd ldnsutils openssh-client \&\& touch /var/log/nsd.log \&\& chown nsd:nsd /var/log/nsd.log \&\& service nsd start|' \

#   -e 's|^source setup/firstuser.sh$|#source setup/firstuser.sh|' \
