# MIAC: INSTALL

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# questions.sh
#
echo MIAC INSTALL questions.sh

	# Install 'dialog' so we can ask the user questions. The original motivation for
	# this was being able to ask the user for input even if stdin has been redirected,
	# e.g. if we piped a bootstrapping install script to bash to get started. In that
	# case, the nifty '[ -t 0 ]' test won't work. But with Vagrant we must suppress so we
	# use a shell flag instead. Really suppress any output from installing dialog.
	#
	# Also install dependencies needed to validate the email address.
	if [ ! -f /usr/bin/dialog ] || [ ! -f /usr/bin/python3 ] || [ ! -f /usr/bin/pip3 ]; then
		echo Installing packages needed for setup...
		apt-get -q -q update
		apt_get_quiet install dialog python3 python3-pip  || exit 1
	fi

	# Installing email_validator is repeated in setup/management.sh, but in setup/management.sh
	# we install it inside a virtualenv. In this script, we don't have the virtualenv yet
	# so we install the python package globally.
	hide_output pip3 install "email_validator>=1.0.0" || exit 1



######################################################################
#
# system.sh
#
echo MIAC INSTALL system.sh

    # ### Add PPAs.

    # We install some non-standard Ubuntu packages maintained by other
    # third-party providers. First ensure add-apt-repository is installed.

    if [ ! -f /usr/bin/add-apt-repository ]; then
	echo "Installing add-apt-repository..."
	hide_output apt-get update
	apt_install software-properties-common
    fi

    # Ensure the universe repository is enabled since some of our packages
    # come from there and minimal Ubuntu installs may have it turned off.
    hide_output add-apt-repository -y universe

    # Install the duplicity PPA.
    hide_output add-apt-repository -y ppa:duplicity-team/duplicity-release-git

    # Stock PHP is now 8.1, but we're transitioning through 8.0 because
    # of Nextcloud.
    hide_output add-apt-repository --y ppa:ondrej/php

# ### Update Packages

# Update system packages to make sure we have the latest upstream versions
# of things from Ubuntu, as well as the directory of packages provide by the
# PPAs so we can install those packages later.

echo Updating system packages...
hide_output apt-get update
apt_get_quiet upgrade

# Old kernels pile up over time and take up a lot of disk space, and because of Mail-in-a-Box
# changes there may be other packages that are no longer needed. Clear out anything apt knows
# is safe to delete.

apt_get_quiet autoremove

# ### Install System Packages

# Install basic utilities.
#
# * unattended-upgrades: Apt tool to install security updates automatically.
# * cron: Runs background processes periodically.
# * ntp: keeps the system time correct
# * fail2ban: scans log files for repeated failed login attempts and blocks the remote IP at the firewall
# * netcat-openbsd: `nc` command line networking tool
# * git: we install some things directly from github
# * sudo: allows privileged users to execute commands as root without being root
# * coreutils: includes `nproc` tool to report number of processors, mktemp
# * bc: allows us to do math to compute sane defaults
# * openssh-client: provides ssh-keygen

echo Installing system packages...
apt_install python3 python3-dev python3-pip python3-setuptools \
	netcat-openbsd wget curl git sudo coreutils bc file \
	pollinate openssh-client unzip \
	unattended-upgrades cron ntp fail2ban rsyslog



######################################################################
#
# resolv.sh
#
echo MIAC INSTALL resolv.sh

apt_install bind9



######################################################################
#
# ssl.sh
#
echo MIAC INSTALL ssl.sh

# Install openssl.

apt_install openssl



######################################################################
#
# dns.sh
#
echo MIAC INSTALL dns.sh

# Install the packages.
#
# * nsd: The non-recursive nameserver that publishes our DNS records.
# * ldnsutils: Helper utilities for signing DNSSEC zones.
# * openssh-client: Provides ssh-keyscan which we use to create SSHFP records.
echo "Installing nsd (DNS server)..."

apt_install nsd ldnsutils openssh-client



######################################################################
#
# mail-postfix.sh
#
echo MIAC INSTALL mail-postfix.sh

# ### Install packages.

# Install postfix's packages.
#
# * `postfix`: The SMTP server.
# * `postfix-pcre`: Enables header filtering.
# * `postgrey`: A mail policy service that soft-rejects mail the first time
#   it is received. Spammers don't usually try agian. Legitimate mail
#   always will.
# * `ca-certificates`: A trust store used to squelch postfix warnings about
#   untrusted opportunistically-encrypted connections.
echo "Installing Postfix (SMTP server)..."
apt_install postfix postfix-sqlite postfix-pcre postgrey ca-certificates



######################################################################
#
# mail-dovecot.sh
#
echo MIAC INSTALL mail-dovecot.sh

# Install packages for dovecot. These are all core dovecot plugins,
# but dovecot-lucene is packaged by *us* in the Mail-in-a-Box PPA,
# not by Ubuntu.

echo "Installing Dovecot (IMAP server)..."
apt_install \
	dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sqlite sqlite3 \
	dovecot-sieve dovecot-managesieved



######################################################################
#
# dkim.sh
#
echo MIAC INSTALL dkim.sh

# Install DKIM...
echo Installing OpenDKIM/OpenDMARC...
apt_install opendkim opendkim-tools opendmarc



######################################################################
#
# spamassassin.sh
#
echo MIAC INSTALL spamassassin.sh

# Install packages and basic configuration
# ----------------------------------------

# Install packages.
# libmail-dkim-perl is needed to make the spamassassin DKIM module work.
# For more information see Debian Bug #689414:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=689414
echo "Installing SpamAssassin..."
apt_install spampd razor pyzor dovecot-antispam libmail-dkim-perl



######################################################################
#
# web.sh
#
echo MIAC INSTALL web.sh

# Some Ubuntu images start off with Apache. Remove it since we
# will use nginx. Use autoremove to remove any Apache depenencies.
if [ -f /usr/sbin/apache2 ]; then
	echo Removing apache...
	hide_output apt-get -y purge apache2 apache2-*
	hide_output apt-get -y --purge autoremove
fi

# Install nginx and a PHP FastCGI daemon.
#
# Turn off nginx's default website.

echo "Installing Nginx (web server)..."

apt_install nginx php${PHP_VER}-cli php${PHP_VER}-fpm idn2

rm -f /etc/nginx/sites-enabled/default



######################################################################
#
# webmail.sh
#
echo MIAC INSTALL webmail.sh

# ### Installing Roundcube

# We install Roundcube from sources, rather than from Ubuntu, because:
#
# 1. Ubuntu's `roundcube-core` package has dependencies on Apache & MySQL, which we don't want.
#
# 2. The Roundcube shipped with Ubuntu is consistently out of date.
#
# 3. It's packaged incorrectly --- it seems to be missing a directory of files.
#
# So we'll use apt-get to manually install the dependencies of roundcube that we know we need,
# and then we'll manually install roundcube from source.

# These dependencies are from `apt-cache showpkg roundcube-core`.
echo "Installing Roundcube (webmail)..."
apt_install \
	dbconfig-common \
	php${PHP_VER}-cli php${PHP_VER}-sqlite3 php${PHP_VER}-intl php${PHP_VER}-common php${PHP_VER}-curl php${PHP_VER}-imap \
	php${PHP_VER}-gd php${PHP_VER}-pspell php${PHP_VER}-mbstring libjs-jquery libjs-jquery-mousewheel libmagic1

# Install Roundcube from source if it is not already present or if it is out of date.
# Combine the Roundcube version number with the commit hash of plugins to track
# whether we have the latest version of everything.
# For the latest versions, see:
#   https://github.com/roundcube/roundcubemail/releases
#   https://github.com/mfreiholz/persistent_login/commits/master
#   https://github.com/stremlau/html5_notifier/commits/master
#   https://github.com/mstilkerich/rcmcarddav/releases
# The easiest way to get the package hashes is to run this script and get the hash from
# the error message.
VERSION=1.6.0
HASH=fd84b4fac74419bb73e7a3bcae1978d5589c52de
PERSISTENT_LOGIN_VERSION=bde7b6840c7d91de627ea14e81cf4133cbb3c07a # version 5.2
HTML5_NOTIFIER_VERSION=68d9ca194212e15b3c7225eb6085dbcf02fd13d7 # version 0.6.4+
CARDDAV_VERSION=4.4.3
CARDDAV_HASH=74f8ba7aee33e78beb9de07f7f44b81f6071b644

UPDATE_KEY=$VERSION:$PERSISTENT_LOGIN_VERSION:$HTML5_NOTIFIER_VERSION:$CARDDAV_VERSION


# MIAC factor into image install and runtime migrate...

needs_update=0 #NODOC
if [ ! -f /usr/local/lib/roundcubemail/version ]; then
	# not installed yet #NODOC
	needs_update=1 #NODOC
elif [[ "$UPDATE_KEY" != $(cat /usr/local/lib/roundcubemail/version) ]]; then
	# checks if the version is what we want
	needs_update=1 #NODOC
fi
if [ $needs_update == 1 ]; then
  # if upgrading from 1.3.x, clear the temp_dir
  if [ -f /usr/local/lib/roundcubemail/version ]; then
    if [ "$(cat /usr/local/lib/roundcubemail/version | cut -c1-3)" == '1.3' ]; then
      find /var/tmp/roundcubemail/ -type f ! -name 'RCMTEMP*' -delete
    fi
  fi

	# install roundcube
	wget_verify \
		https://github.com/roundcube/roundcubemail/releases/download/$VERSION/roundcubemail-$VERSION-complete.tar.gz \
		$HASH \
		/tmp/roundcube.tgz
	tar -C /usr/local/lib --no-same-owner -zxf /tmp/roundcube.tgz
	rm -rf /usr/local/lib/roundcubemail
	mv /usr/local/lib/roundcubemail-$VERSION/ $RCM_DIR
	rm -f /tmp/roundcube.tgz

	# install roundcube persistent_login plugin
	git_clone https://github.com/mfreiholz/Roundcube-Persistent-Login-Plugin.git $PERSISTENT_LOGIN_VERSION '' ${RCM_PLUGIN_DIR}/persistent_login

	# install roundcube html5_notifier plugin
	git_clone https://github.com/kitist/html5_notifier.git $HTML5_NOTIFIER_VERSION '' ${RCM_PLUGIN_DIR}/html5_notifier

	# download and verify the full release of the carddav plugin
	wget_verify \
		https://github.com/mstilkerich/rcmcarddav/releases/download/v${CARDDAV_VERSION}/carddav-v${CARDDAV_VERSION}.tar.gz \
		$CARDDAV_HASH \
		/tmp/carddav.tar.gz

	# unzip and cleanup
	tar -C ${RCM_PLUGIN_DIR} -zxf /tmp/carddav.tar.gz
	rm -f /tmp/carddav.tar.gz

	# record the version we've installed
	echo $UPDATE_KEY > ${RCM_DIR}/version
fi



######################################################################
#
# nextcloud.sh
#
echo MIAC INSTALL nextcloud.sh

# ### Installing Nextcloud

echo "Installing Nextcloud (contacts/calendar)..."

# Nextcloud core and app (plugin) versions to install.
# With each version we store a hash to ensure we install what we expect.

# Nextcloud core
# --------------
# * See https://nextcloud.com/changelog for the latest version.
# * Check https://docs.nextcloud.com/server/latest/admin_manual/installation/system_requirements.html
#   for whether it supports the version of PHP available on this machine.
# * Since Nextcloud only supports upgrades from consecutive major versions,
#   we automatically install intermediate versions as needed.
# * The hash is the SHA1 hash of the ZIP package, which you can find by just running this script and
#   copying it from the error message when it doesn't match what is below.
nextcloud_ver=23.0.10
nextcloud_hash=8831c7862e39460fbb789bacac8729fab0ba02dd

# Nextcloud apps
# --------------
# * Find the most recent tag that is compatible with the Nextcloud version above by
#   consulting the <dependencies>...<nextcloud> node at:
#   https://github.com/nextcloud-releases/contacts/blob/main/appinfo/info.xml
#   https://github.com/nextcloud-releases/calendar/blob/main/appinfo/info.xml
#   https://github.com/nextcloud/user_external/blob/master/appinfo/info.xml
# * The hash is the SHA1 hash of the ZIP package, which you can find by just running this script and
#   copying it from the error message when it doesn't match what is below.
contacts_ver=4.2.2
contacts_hash=ca13d608ed8955aa374cb4f31b6026b57ef88887
calendar_ver=3.5.1
calendar_hash=c8136a3deb872a3ef73ce1155b58f3ab27ec7110
user_external_ver=3.0.0
user_external_hash=0df781b261f55bbde73d8c92da3f99397000972f

# Clear prior packages and install dependencies from apt.

apt-get purge -qq -y owncloud* # we used to use the package manager

apt_install curl php${PHP_VER} php${PHP_VER}-fpm \
	php${PHP_VER}-cli php${PHP_VER}-sqlite3 php${PHP_VER}-gd php${PHP_VER}-imap php${PHP_VER}-curl \
	php${PHP_VER}-dev php${PHP_VER}-gd php${PHP_VER}-xml php${PHP_VER}-mbstring php${PHP_VER}-zip php${PHP_VER}-apcu \
	php${PHP_VER}-intl php${PHP_VER}-imagick php${PHP_VER}-gmp php${PHP_VER}-bcmath


# MIAC nextcloud install/upgrade is complicated because of how install/backup/migrate/conf/update are all mixed together...
# MIAC Note: uses $STORAGE_ROOT
# MIAC TODO: figure out if/how to support pre-miac installations...
# MIAC TODO: factor install semantics from MIAC-specific backup/migrate/conf/update

InstallNextcloud() {

	version=$1
	hash=$2
	version_contacts=$3
	hash_contacts=$4
	version_calendar=$5
	hash_calendar=$6
	version_user_external=${7:-}
	hash_user_external=${8:-}

	echo
	echo "Upgrading to Nextcloud version $version"
	echo

        # Download and verify
        wget_verify https://download.nextcloud.com/server/releases/nextcloud-$version.zip $hash /tmp/nextcloud.zip

	# Remove the current owncloud/Nextcloud
	rm -rf /usr/local/lib/owncloud

	# Extract ownCloud/Nextcloud
	unzip -q /tmp/nextcloud.zip -d /usr/local/lib
	mv /usr/local/lib/nextcloud /usr/local/lib/owncloud
	rm -f /tmp/nextcloud.zip

	# The two apps we actually want are not in Nextcloud core. Download the releases from
	# their github repositories.
	mkdir -p /usr/local/lib/owncloud/apps

	wget_verify https://github.com/nextcloud-releases/contacts/archive/refs/tags/v$version_contacts.tar.gz $hash_contacts /tmp/contacts.tgz
	tar xf /tmp/contacts.tgz -C /usr/local/lib/owncloud/apps/
	rm /tmp/contacts.tgz

	wget_verify https://github.com/nextcloud-releases/calendar/archive/refs/tags/v$version_calendar.tar.gz $hash_calendar /tmp/calendar.tgz
	tar xf /tmp/calendar.tgz -C /usr/local/lib/owncloud/apps/
	rm /tmp/calendar.tgz

	# Starting with Nextcloud 15, the app user_external is no longer included in Nextcloud core,
	# we will install from their github repository.
	if [ -n "$version_user_external" ]; then
		wget_verify https://github.com/nextcloud-releases/user_external/releases/download/v$version_user_external/user_external-v$version_user_external.tar.gz $hash_user_external /tmp/user_external.tgz
		tar -xf /tmp/user_external.tgz -C /usr/local/lib/owncloud/apps/
		rm /tmp/user_external.tgz
	fi

	# Fix weird permissions.
	chmod 750 /usr/local/lib/owncloud/{apps,config}

	# MIAC consider install/generic/conf refactoring to start here...

	# MIAC generic

	# Create a symlink to the config.php in STORAGE_ROOT (for upgrades we're restoring the symlink we previously
	# put in, and in new installs we're creating a symlink and will create the actual config later).
	ln -sf $STORAGE_ROOT/owncloud/config.php /usr/local/lib/owncloud/config/config.php

	# Make sure permissions are correct or the upgrade step won't run.
	# $STORAGE_ROOT/owncloud may not yet exist, so use -f to suppress
	# that error.
	chown -f -R www-data.www-data $STORAGE_ROOT/owncloud /usr/local/lib/owncloud || /bin/true

	# MIAC third-party migrate

	# If this isn't a new installation, immediately run the upgrade script.
	# Then check for success (0=ok and 3=no upgrade needed, both are success).
	if [ -e $STORAGE_ROOT/owncloud/owncloud.db ]; then
		# ownCloud 8.1.1 broke upgrades. It may fail on the first attempt, but
		# that can be OK.
		sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/occ upgrade
		if [ \( $? -ne 0 \) -a \( $? -ne 3 \) ]; then
			echo "Trying ownCloud upgrade again to work around ownCloud upgrade bug..."
			sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/occ upgrade
			if [ \( $? -ne 0 \) -a \( $? -ne 3 \) ]; then exit 1; fi
			sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/occ maintenance:mode --off
			echo "...which seemed to work."
		fi

		# Add missing indices. NextCloud didn't include this in the normal upgrade because it might take some time.
		sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/occ db:add-missing-indices

		# Run conversion to BigInt identifiers, this process may take some time on large tables.
		sudo -u www-data php$PHP_VER /usr/local/lib/owncloud/occ db:convert-filecache-bigint --no-interaction
	fi
}

# MIAC migrate/version/state semantics

# Current Nextcloud Version, #1623
# Checking /usr/local/lib/owncloud/version.php shows version of the Nextcloud application, not the DB
# $STORAGE_ROOT/owncloud is kept together even during a backup.  It is better to rely on config.php than
# version.php since the restore procedure can leave the system in a state where you have a newer Nextcloud
# application version than the database.

# If config.php exists, get version number, otherwise CURRENT_NEXTCLOUD_VER is empty.
if [ -f "$STORAGE_ROOT/owncloud/config.php" ]; then
	CURRENT_NEXTCLOUD_VER=$(php$PHP_VER -r "include(\"$STORAGE_ROOT/owncloud/config.php\"); echo(\$CONFIG['version']);")
else
	CURRENT_NEXTCLOUD_VER=""
fi

# MIAC initial install is simple compared to migrate/update

# If the Nextcloud directory is missing (never been installed before, or the nextcloud version to be installed is different
# from the version currently installed, do the install/upgrade
if [ ! -d /usr/local/lib/owncloud/ ] || [[ ! ${CURRENT_NEXTCLOUD_VER} =~ ^$nextcloud_ver ]]; then

	# Stop php-fpm if running. If they are not running (which happens on a previously failed install), dont bail.
	service php$PHP_VER-fpm stop &> /dev/null || /bin/true

	# Backup the existing ownCloud/Nextcloud.
	# Create a backup directory to store the current installation and database to
	BACKUP_DIRECTORY=$STORAGE_ROOT/owncloud-backup/$(date +"%Y-%m-%d-%T")
	mkdir -p "$BACKUP_DIRECTORY"
	if [ -d /usr/local/lib/owncloud/ ]; then
		echo "Upgrading Nextcloud --- backing up existing installation, configuration, and database to directory to $BACKUP_DIRECTORY..."
		cp -r /usr/local/lib/owncloud "$BACKUP_DIRECTORY/owncloud-install"
	fi
	if [ -e $STORAGE_ROOT/owncloud/owncloud.db ]; then
		cp $STORAGE_ROOT/owncloud/owncloud.db $BACKUP_DIRECTORY
	fi
	if [ -e $STORAGE_ROOT/owncloud/config.php ]; then
		cp $STORAGE_ROOT/owncloud/config.php $BACKUP_DIRECTORY
	fi

	# If ownCloud or Nextcloud was previously installed....
	if [ ! -z ${CURRENT_NEXTCLOUD_VER} ]; then
		# Database migrations from ownCloud are no longer possible because ownCloud cannot be run under
		# PHP 7.
		if [[ ${CURRENT_NEXTCLOUD_VER} =~ ^[89] ]]; then
			echo "Upgrades from Mail-in-a-Box prior to v0.28 (dated July 30, 2018) with Nextcloud < 13.0.6 (you have ownCloud 8 or 9) are not supported. Upgrade to Mail-in-a-Box version v0.30 first. Setup will continue, but skip the Nextcloud migration."
			return 0
		elif [[ ${CURRENT_NEXTCLOUD_VER} =~ ^1[012] ]]; then
			echo "Upgrades from Mail-in-a-Box prior to v0.28 (dated July 30, 2018) with Nextcloud < 13.0.6 (you have ownCloud 10, 11 or 12) are not supported. Upgrade to Mail-in-a-Box version v0.30 first. Setup will continue, but skip the Nextcloud migration."
			return 0
		elif [[ ${CURRENT_NEXTCLOUD_VER} =~ ^1[3456789] ]]; then
			echo "Upgrades from Mail-in-a-Box prior to v60 with Nextcloud 19 or earlier are not supported. Upgrade to the latest Mail-in-a-Box version supported on your machine first. Setup will continue, but skip the Nextcloud migration."
			return 0
		fi
		if [[ ${CURRENT_NEXTCLOUD_VER} =~ ^20 ]]; then
			InstallNextcloud 21.0.7 f5c7079c5b56ce1e301c6a27c0d975d608bb01c9 4.0.7 45e7cf4bfe99cd8d03625cf9e5a1bb2e90549136 3.0.4 d0284b68135777ec9ca713c307216165b294d0fe
			CURRENT_NEXTCLOUD_VER="21.0.7"
		fi
		if [[ ${CURRENT_NEXTCLOUD_VER} =~ ^21 ]]; then
			InstallNextcloud 22.2.6 9d39741f051a8da42ff7df46ceef2653a1dc70d9 4.1.0 697f6b4a664e928d72414ea2731cb2c9d1dc3077 3.2.2 ce4030ab57f523f33d5396c6a81396d440756f5f 3.0.0 0df781b261f55bbde73d8c92da3f99397000972f
			CURRENT_NEXTCLOUD_VER="22.2.6"
		fi
	fi

	InstallNextcloud $nextcloud_ver $nextcloud_hash $contacts_ver $contacts_hash $calendar_ver $calendar_hash $user_external_ver $user_external_hash
fi



######################################################################
#
# zpush.sh
#
echo MIAC INSTALL zpush.sh

# Prereqs.

echo "Installing Z-Push (Exchange/ActiveSync server)..."
apt_install \
       php${PHP_VER}-soap php${PHP_VER}-imap libawl-php php$PHP_VER-xml

phpenmod -v $PHP_VER imap

# Copy Z-Push into place.
VERSION=2.6.2
TARGETHASH=f0e8091a8030e5b851f5ba1f9f0e1a05b8762d80
needs_update=0 #NODOC
if [ ! -f /usr/local/lib/z-push/version ]; then
	needs_update=1 #NODOC
elif [[ $VERSION != $(cat /usr/local/lib/z-push/version) ]]; then
	# checks if the version
	needs_update=1 #NODOC
fi
if [ $needs_update == 1 ]; then
	# Download
	wget_verify "https://github.com/Z-Hub/Z-Push/archive/refs/tags/$VERSION.zip" $TARGETHASH /tmp/z-push.zip

	# Extract into place.
	rm -rf /usr/local/lib/z-push /tmp/z-push
	unzip -q /tmp/z-push.zip -d /tmp/z-push
	mv /tmp/z-push/*/src /usr/local/lib/z-push
	rm -rf /tmp/z-push.zip /tmp/z-push

	rm -f /usr/sbin/z-push-{admin,top}
	echo $VERSION > /usr/local/lib/z-push/version
fi



######################################################################
#
# management.sh
#
echo MIAC INSTALL management.sh

echo "Installing Mail-in-a-Box system management daemon..."

# DEPENDENCIES

# duplicity is used to make backups of user data.
#
# virtualenv is used to isolate the Python 3 packages we
# install via pip from the system-installed packages.
#
# certbot installs EFF's certbot which we use to
# provision free TLS certificates.
apt_install duplicity python3-pip virtualenv certbot rsync

# b2sdk is used for backblaze backups.
# boto3 is used for amazon aws backups.
# Both are installed outside the pipenv, so they can be used by duplicity
hide_output pip3 install --upgrade b2sdk boto3

# Create a virtualenv for the installation of Python 3 packages
# used by the management daemon.


mkdir -p $inst_dir
if [ ! -d $venv ]; then
	hide_output virtualenv -ppython3 $venv
fi

# Upgrade pip because the Ubuntu-packaged version is out of date.
hide_output $venv/bin/pip install --upgrade pip

# Install other Python 3 packages used by the management daemon.
# The first line is the packages that Josh maintains himself!
# NOTE: email_validator is repeated in setup/questions.sh, so please keep the versions synced.
# MIAC adds final line: pythondialog validators
hide_output $venv/bin/pip install --upgrade \
	rtyaml "email_validator>=1.0.0" "exclusiveprocess" \
	flask dnspython python-dateutil expiringdict gunicorn \
	qrcode[pil] pyotp \
	"idna>=2.0.0" "cryptography==37.0.2" psutil postfix-mta-sts-resolver \
	b2sdk boto3 \
	pythondialog validators

# CONFIGURATION


# Download jQuery and Bootstrap local files

# Make sure we have the directory to save to.
assets_dir=$inst_dir/vendor/assets
rm -rf $assets_dir
mkdir -p $assets_dir

# jQuery CDN URL
jquery_version=2.1.4
jquery_url=https://code.jquery.com

# Get jQuery
wget_verify $jquery_url/jquery-$jquery_version.min.js 43dc554608df885a59ddeece1598c6ace434d747 $assets_dir/jquery.min.js

# Bootstrap CDN URL
bootstrap_version=3.3.7
bootstrap_url=https://github.com/twbs/bootstrap/releases/download/v$bootstrap_version/bootstrap-$bootstrap_version-dist.zip

# Get Bootstrap
wget_verify $bootstrap_url e6b1000b94e835ffd37f4c6dcbdad43f4b48a02a /tmp/bootstrap.zip
unzip -q /tmp/bootstrap.zip -d $assets_dir
mv $assets_dir/bootstrap-$bootstrap_version-dist $assets_dir/bootstrap
rm -f /tmp/bootstrap.zip



######################################################################
#
# munin.sh
#
echo MIAC INSTALL munin.sh

# install Munin
echo "Installing Munin (system monitoring)..."
apt_install munin munin-node libcgi-fast-perl
# libcgi-fast-perl is needed by /usr/lib/munin/cgi/munin-cgi-graph


# ensure success code when this script is sourced
/bin/true

