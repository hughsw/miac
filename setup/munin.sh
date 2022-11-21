##### MIAC_BOILERPLATE_BEGIN

#!/bin/bash
# Munin: resource monitoring tool
#################################################

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

##### MIAC_BOILERPLATE_END


##### MIAC_INSTALL_BEGIN

# install Munin
echo "Installing Munin (system monitoring)..."
apt_install munin munin-node libcgi-fast-perl
# libcgi-fast-perl is needed by /usr/lib/munin/cgi/munin-cgi-graph

##### MIAC_INSTALL_END


##### MIAC_GENERIC_BEGIN

# The Debian installer touches these files and chowns them to www-data:adm for use with spawn-fcgi
chown munin /var/log/munin/munin-cgi-html.log
chown munin /var/log/munin/munin-cgi-graph.log

##### MIAC_GENERIC_END


##### MIAC_CONF_BEGIN

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

##### MIAC_CONF_END


##### MIAC_GENERIC_BEGIN

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

##### MIAC_GENERIC_END


##### MIAC_SYSTEMD_BEGIN

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

##### MIAC_SYSTEMD_END
