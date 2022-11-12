
##### MIAC_SYSTEMD_BEGIN

# Wait for the management daemon to start...
until nc -z -w 4 127.0.0.1 10222
do
    # MIAC include a failure timeout
    echo Waiting for the Mail-in-a-Box management daemon to start...
    sleep 2
done

# ...and then have it write the DNS and nginx configuration files and start those
# services.
tools/dns_update
tools/web_update

# Give fail2ban another restart. The log files may not all have been present when
# fail2ban was first configured, but they should exist now.
restart_service fail2ban

##### MIAC_SYSTEMD_END
