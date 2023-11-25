# MIAC: SSL

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# system.sh
#
echo MIAC SSL system.sh

# ### Seed /dev/urandom
#
# /dev/urandom is used by various components for generating random bytes for
# encryption keys and passwords:
#
# * TLS private key (see `ssl.sh`, which calls `openssl genrsa`)
# * DNSSEC signing keys (see `dns.sh`)
# * our management server's API key (via Python's os.urandom method)
# * Roundcube's SECRET_KEY (`webmail.sh`)
#
# Why /dev/urandom? It's the same as /dev/random, except that it doesn't wait
# for a constant new stream of entropy. In practice, we only need a little
# entropy at the start to get going. After that, we can safely pull a random
# stream from /dev/urandom and not worry about how much entropy has been
# added to the stream. (http://www.2uo.de/myths-about-urandom/) So we need
# to worry about /dev/urandom being seeded properly (which is also an issue
# for /dev/random), but after that /dev/urandom is superior to /dev/random
# because it's faster and doesn't block indefinitely to wait for hardware
# entropy. Note that `openssl genrsa` even uses `/dev/urandom`, and if it's
# good enough for generating an RSA private key, it's good enough for anything
# else we may need.
#
# Now about that seeding issue....
#
# /dev/urandom is seeded from "the uninitialized contents of the pool buffers when
# the kernel starts, the startup clock time in nanosecond resolution,...and
# entropy saved across boots to a local file" as well as the order of
# execution of concurrent accesses to /dev/urandom. (Heninger et al 2012,
# https://factorable.net/weakkeys12.conference.pdf) But when memory is zeroed,
# the system clock is reset on boot, /etc/init.d/urandom has not yet run, or
# the machine is single CPU or has no concurrent accesses to /dev/urandom prior
# to this point, /dev/urandom may not be seeded well. After this, /dev/urandom
# draws from the same entropy sources as /dev/random, but it doesn't block or
# issue any warnings if no entropy is actually available. (http://www.2uo.de/myths-about-urandom/)
# Entropy might not be readily available because this machine has no user input
# devices (common on servers!) and either no hard disk or not enough IO has
# ocurred yet --- although haveged tries to mitigate this. So there's a good chance
# that accessing /dev/urandom will not be drawing from any hardware entropy and under
# a perfect-storm circumstance where the other seeds are meaningless, /dev/urandom
# may not be seeded at all.
#
# The first thing we'll do is block until we can seed /dev/urandom with enough
# hardware entropy to get going, by drawing from /dev/random. haveged makes this
# less likely to stall for very long.

echo Initializing system random number generator...
dd if=/dev/random of=/dev/urandom bs=1 count=32 2> /dev/null




# Between these two, we really ought to be all set.






######################################################################
#
# ssl.sh
#
echo MIAC SSL ssl.sh

#!/bin/bash
#
# RSA private key, SSL certificate, Diffie-Hellman bits files
# -------------------------------------------

# Create an RSA private key, a self-signed SSL certificate, and some
# Diffie-Hellman cipher bits, if they have not yet been created.
#
# The RSA private key and certificate are used for:
#
#  * DNSSEC DANE TLSA records
#  * IMAP
#  * SMTP (opportunistic TLS for port 25 and submission on ports 465/587)
#  * HTTPS
#
# The certificate is created with its CN set to the PRIMARY_HOSTNAME. It is
# also used for other domains served over HTTPS until the user installs a
# better certificate for those domains.
#
# The Diffie-Hellman cipher bits are used for SMTP and HTTPS, when a
# Diffie-Hellman cipher is selected during TLS negotiation. Diffie-Hellman
# provides Perfect Forward Secrecy.


# Show a status line if we are going to take any action in this file.
if  [ ! -f /usr/bin/openssl ] \
 || [ ! -f $STORAGE_ROOT/ssl/ssl_private_key.pem ] \
 || [ ! -f $STORAGE_ROOT/ssl/ssl_certificate.pem ] \
 || [ ! -f $STORAGE_ROOT/ssl/dh2048.pem ]; then
	echo "Creating initial SSL certificate and perfect forward secrecy Diffie-Hellman parameters..."
fi


# Generate a new private key.
#
# The key is only as good as the entropy available to openssl so that it
# can generate a random key. "OpenSSL’s built-in RSA key generator ....
# is seeded on first use with (on Linux) 32 bytes read from /dev/urandom,
# the process ID, user ID, and the current time in seconds. [During key
# generation OpenSSL] mixes into the entropy pool the current time in seconds,
# the process ID, and the possibly uninitialized contents of a ... buffer
# ... dozens to hundreds of times."
#
# A perfect storm of issues can cause the generated key to be not very random:
#
#   * improperly seeded /dev/urandom, but see system.sh for how we mitigate this
#   * the user ID of this process is always the same (we're root), so that seed is useless
#   * zero'd memory (plausible on embedded systems, cloud VMs?)
#   * a predictable process ID (likely on an embedded/virtualized system)
#   * a system clock reset to a fixed time on boot
#
# Since we properly seed /dev/urandom in system.sh we should be fine, but I leave
# in the rest of the notes in case that ever changes.
if [ ! -f $STORAGE_ROOT/ssl/ssl_private_key.pem ]; then
	# Set the umask so the key file is never world-readable.
	(umask 077; hide_output \
		openssl genrsa -out $STORAGE_ROOT/ssl/ssl_private_key.pem 2048)
fi

# Generate a self-signed SSL certificate because things like nginx, dovecot,
# etc. won't even start without some certificate in place, and we need nginx
# so we can offer the user a control panel to install a better certificate.
if [ ! -f $STORAGE_ROOT/ssl/ssl_certificate.pem ]; then
    # Generate a certificate signing request.
    CSR=/tmp/ssl_cert_sign_req-$$.csr
    hide_output \
	openssl req -new -key $STORAGE_ROOT/ssl/ssl_private_key.pem -out $CSR \
	-sha256 -subj "/CN=$PRIMARY_HOSTNAME"

    # Generate the self-signed certificate.
    CERT=$STORAGE_ROOT/ssl/$PRIMARY_HOSTNAME-selfsigned-$(date --rfc-3339=date | sed s/-//g).pem
    hide_output \
	openssl x509 -req -days 365 \
	-in $CSR -signkey $STORAGE_ROOT/ssl/ssl_private_key.pem -out $CERT

    # Delete the certificate signing request because it has no other purpose.
    rm -f $CSR

    # Symlink the certificate into the system certificate path, so system services
    # can find it.
    ln -s $CERT $STORAGE_ROOT/ssl/ssl_certificate.pem
fi

# Generate some Diffie-Hellman cipher bits.
# openssl's default bit length for this is 1024 bits, but we'll create
# 2048 bits of bits per the latest recommendations.
if [ ! -f $STORAGE_ROOT/ssl/dh2048.pem ]; then
	# MIAC adds -dsaparam to speed this up during development
	# MIAC TODO: switch to single-use DH bits, e.g. daily cron refresh...
	# MIAC: https://www.openssl.org/news/secadv/20160128.txt
	# MIAC: https://security.stackexchange.com/questions/95178/diffie-hellman-parameters-still-calculating-after-24-hours?
	# MIAC: lack of good guardrail guidance on this technical matter...
	openssl dhparam -dsaparam -out $STORAGE_ROOT/ssl/dh2048.pem 2048
fi



######################################################################
#
# dns.sh
#
echo MIAC SSL dns.sh

# Create DNSSEC signing keys.

# TLDs, registrars, and validating nameservers don't all support the same algorithms,
# so we'll generate keys using a few different algorithms so that dns_update.py can
# choose which algorithm to use when generating the zonefiles. See #1953 for recent
# discussion. File for previously used algorithms (i.e. RSASHA1-NSEC3-SHA1) may still
# be in the output directory, and we'll continue to support signing zones with them
# so that trust isn't broken with deployed DS records, but we won't generate those
# keys on new systems.
FIRST=1 #NODOC
for algo in RSASHA256 ECDSAP256SHA256; do
if [ ! -f "$STORAGE_ROOT/dns/dnssec/$algo.conf" ]; then
	if [ $FIRST == 1 ]; then
		echo "Generating DNSSEC signing keys..."
		FIRST=0 #NODOC
	fi

	# Create the Key-Signing Key (KSK) (with `-k`) which is the so-called
	# Secure Entry Point. The domain name we provide ("_domain_") doesn't
	# matter -- we'll use the same keys for all our domains.
	#
	# `ldns-keygen` outputs the new key's filename to stdout, which
	# we're capturing into the `KSK` variable.
	#
	# ldns-keygen uses /dev/random for generating random numbers by default.
	# This is slow and unecessary if we ensure /dev/urandom is seeded properly,
	# so we use /dev/urandom. See system.sh for an explanation. See #596, #115.
	# (This previously used -b 2048 but it's unclear if this setting makes sense
	# for non-RSA keys, so it's removed. The RSA-based keys are not recommended
	# anymore anyway.)
	KSK=$(umask 077; cd $STORAGE_ROOT/dns/dnssec; ldns-keygen -r /dev/urandom -a $algo -k _domain_);

	# Now create a Zone-Signing Key (ZSK) which is expected to be
	# rotated more often than a KSK, although we have no plans to
	# rotate it (and doing so would be difficult to do without
	# disturbing DNS availability.) Omit `-k`.
	# (This previously used -b 1024 but it's unclear if this setting makes sense
	# for non-RSA keys, so it's removed.)
	ZSK=$(umask 077; cd $STORAGE_ROOT/dns/dnssec; ldns-keygen -r /dev/urandom -a $algo _domain_);

	# These generate two sets of files like:
	#
	# * `K_domain_.+007+08882.ds`: DS record normally provided to domain name registrar (but it's actually invalid with `_domain_` so we don't use this file)
	# * `K_domain_.+007+08882.key`: public key
	# * `K_domain_.+007+08882.private`: private key (secret!)

	# The filenames are unpredictable and encode the key generation
	# options. So we'll store the names of the files we just generated.
	# We might have multiple keys down the road. This will identify
	# what keys are the current keys.
	cat > $STORAGE_ROOT/dns/dnssec/$algo.conf << EOF;
KSK=$KSK
ZSK=$ZSK
EOF
fi

	# And loop to do the next algorithm...
done



######################################################################
#
# dkim.sh
#
echo MIAC SSL dkim.sh

# Create a new DKIM key. This creates mail.private and mail.txt
# in $STORAGE_ROOT/mail/dkim. The former is the private key and
# the latter is the suggested DNS TXT entry which we'll include
# in our DNS setup. Note that the files are named after the
# 'selector' of the key, which we can change later on to support
# key rotation.
#
# A 1024-bit key is seen as a minimum standard by several providers
# such as Google. But they and others use a 2048 bit key, so we'll
# do the same. Keys beyond 2048 bits may exceed DNS record limits.
if [ ! -f "$STORAGE_ROOT/mail/dkim/mail.private" ]; then
	opendkim-genkey -b 2048 -r -s mail -D $STORAGE_ROOT/mail/dkim
fi

# Ensure files are owned by the opendkim user and are private otherwise.
chown -R opendkim:opendkim $STORAGE_ROOT/mail/dkim
chmod go-rwx $STORAGE_ROOT/mail/dkim



######################################################################
#
# web.sh
#
echo MIAC SSL web.sh

cat conf/ios-profile.xml \
	| sed "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" \
	| sed "s/UUID1/$(cat /proc/sys/kernel/random/uuid)/" \
	| sed "s/UUID2/$(cat /proc/sys/kernel/random/uuid)/" \
	| sed "s/UUID3/$(cat /proc/sys/kernel/random/uuid)/" \
	| sed "s/UUID4/$(cat /proc/sys/kernel/random/uuid)/" \
	 > /var/lib/mailinabox/mobileconfig.xml
chmod a+r /var/lib/mailinabox/mobileconfig.xml



######################################################################
#
# management.sh
#
echo MIAC SSL management.sh

# MIAC Note: unlike most secrets, we do not recreate these backup-supporting keys on each run

# Create a backup directory and a random key for encrypting backups.
mkdir -p $STORAGE_ROOT/backup
if [ ! -f $STORAGE_ROOT/backup/secret_key.txt ]; then
	$(umask 077; openssl rand -base64 2048 > $STORAGE_ROOT/backup/secret_key.txt)
fi
# We may need an ssh key to store backups via rsync, if it doesn't exist create one
if [ ! -f $STORAGE_ROOT/backup/id_rsa_miab ]; then
	echo 'Creating SSH key for backup…'
	ssh-keygen -t rsa -b 2048 -a 100 -f $STORAGE_ROOT/backup/id_rsa_miab -N '' -q -C "root@$PRIMARY_HOSTNAME"
fi


# ensure success code when this script is sourced
/bin/true

