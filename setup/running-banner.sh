
##### MIAC_SYSTEMD_BEGIN

# Done.
echo
echo "-----------------------------------------------"
echo
echo Your Mail-in-a-Box is running.
echo
echo Please log in to the control panel for further instructions at:
echo
if management/status_checks.py --check-primary-hostname; then
    # Show the nice URL if it appears to be resolving and has a valid certificate.
    echo https://$PRIMARY_HOSTNAME/admin
    echo
    echo "If you have a DNS problem put the box's IP address in the URL"
    echo "(https://$PUBLIC_IP/admin) but then check the TLS fingerprint:"
    openssl x509 -in $STORAGE_ROOT/ssl/ssl_certificate.pem -noout -fingerprint -sha256\
        | sed "s/SHA256 Fingerprint=//i"
else
    echo https://$PUBLIC_IP/admin
    echo
    echo You will be alerted that the website has an invalid certificate. Check that
    echo the certificate fingerprint matches:
    echo
    openssl x509 -in $STORAGE_ROOT/ssl/ssl_certificate.pem -noout -fingerprint -sha256\
        | sed "s/SHA256 Fingerprint=//i"
    echo
    echo Then you can confirm the security exception and continue.
    echo
fi

##### MIAC_SYSTEMD_END
