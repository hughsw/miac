# MIAC: MIGRATE

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# migrate.sh
#
echo MIAC MIGRATE migrate.sh

# Recall the last settings used if we're running this a second time.
if [ -f /etc/mailinabox.conf ]; then
	# Run any system migrations before proceeding. Since this is a second run,
	# we assume we have Python already installed.
	setup/migrate.py --migrate || exit 1

	# Load the old .conf file to get existing configuration options loaded
	# into variables with a DEFAULT_ prefix.
	# MIAC make sed more selective about changing only shell variable assignments...
	cat /etc/mailinabox.conf | sed 's/^\([[:space:]]*\)\([a-z_][a-z_0-9]*\)=/\1DEFAULT_\2=/i' > /tmp/mailinabox.prev.conf
	#cat /etc/mailinabox.conf | sed s/^/DEFAULT_/ > /tmp/mailinabox.prev.conf
	source /tmp/mailinabox.prev.conf
	rm -f /tmp/mailinabox.prev.conf
else
	FIRST_TIME_SETUP=1
fi



######################################################################
#
# nextcloud.sh
#
echo MIAC MIGRATE nextcloud.sh

# Migrate users_external data from <0.6.0 to version 3.0.0 (see https://github.com/nextcloud/user_external).
# This version was probably in use in Mail-in-a-Box v0.41 (February 26, 2019) and earlier.
# We moved to v0.6.3 in 193763f8. Ignore errors - maybe there are duplicated users with the
# correct backend already.
sqlite3 $STORAGE_ROOT/owncloud/owncloud.db "UPDATE oc_users_external SET backend='127.0.0.1';" || /bin/true


# ensure success code when this script is sourced
/bin/true

