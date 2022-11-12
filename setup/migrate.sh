##### MIAC_MIGRATE_BEGIN

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

##### MIAC_MIGRATE_END
