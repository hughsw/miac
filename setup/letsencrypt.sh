##### MIAC_CONF_BEGIN

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

##### MIAC_CONF_END
