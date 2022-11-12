##### MIAC_CONF_BEGIN

# ### Fail2Ban Service

# Configure the Fail2Ban installation to prevent dumb bruce-force attacks against dovecot, postfix, ssh, etc.
rm -f /etc/fail2ban/jail.local # we used to use this file but don't anymore
rm -f /etc/fail2ban/jail.d/defaults-debian.conf # removes default config so we can manage all of fail2ban rules in one config

    cat conf/fail2ban/jails.conf \
	| sed "s/PUBLIC_IPV6/$PUBLIC_IPV6/g" \
	| sed "s/PUBLIC_IP/$PUBLIC_IP/g" \
	| sed "s#STORAGE_ROOT#$STORAGE_ROOT#" \
	      > /etc/fail2ban/jail.d/mailinabox.conf

##### MIAC_CONF_END


##### MIAC_GENERIC_BEGIN

cp -f conf/fail2ban/filter.d/* /etc/fail2ban/filter.d/

##### MIAC_GENERIC_END


##### MIAC_RUNTIME_BEGIN

# On first installation, the log files that the jails look at don't all exist.
# e.g., The roundcube error log isn't normally created until someone logs into
# Roundcube for the first time. This causes fail2ban to fail to start. Later
# scripts will ensure the files exist and then fail2ban is given another
# restart at the very end of setup.
restart_service fail2ban

##### MIAC_RUNTIME_END
