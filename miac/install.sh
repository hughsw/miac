#!/bin/bash

set -euo pipefail

set -x

# Optimization only to speed up setup/start.sh
# Install packages that we know mailinabox installs (except nsd and bind which have special configuration by mailinabox before installation)

DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dpkg::Options::=--force-confold \
    -o Dpkg::Options::=--force-confdef \
    --assume-yes --allow-downgrades --allow-remove-essential --allow-change-held-packages \
    install \
      bc \
      ca-certificates \
      certbot \
      coreutils \
      cron \
      curl \
      dbconfig-common \
      dialog \
      dovecot-antispam \
      dovecot-core \
      dovecot-imapd \
      dovecot-lmtpd \
      dovecot-managesieved \
      dovecot-pop3d \
      dovecot-sieve \
      dovecot-sqlite \
      duplicity \
      fail2ban \
      file \
      git \
      idn2 \
      ldnsutils \
      libawl-php \
      libcgi-fast-perl \
      libjs-jquery \
      libjs-jquery-mousewheel \
      libmagic1 \
      libmail-dkim-perl \
      munin \
      munin-node \
      netcat-openbsd \
      nginx \
      ntp \
      opendkim \
      opendkim-tools \
      opendmarc \
      openssh-client \
      openssl \
      php8.0 \
      php8.0-apcu \
      php8.0-bcmath \
      php8.0-cli \
      php8.0-common \
      php8.0-curl \
      php8.0-dev \
      php8.0-fpm \
      php8.0-gd \
      php8.0-gmp \
      php8.0-imagick \
      php8.0-imap \
      php8.0-intl \
      php8.0-mbstring \
      php8.0-pspell \
      php8.0-soap \
      php8.0-sqlite3 \
      php8.0-xml \
      php8.0-zip \
      pollinate \
      postfix \
      postfix-pcre \
      postfix-sqlite \
      postgrey \
      python3 \
      python3-dev \
      python3-pip \
      python3-setuptools \
      pyzor \
      razor \
      rsync \
      rsyslog \
      spampd \
      sqlite3 \
      sudo \
      ufw \
      unattended-upgrades \
      unzip \
      virtualenv \
      wget

#      bind9 \
#      iptables \
#      nsd \
#touch /var/log/nsd.log
#chown nsd:nsd /var/log/nsd.log


pip3 install 'email_validator>=1.0.0'
pip3 install --upgrade b2sdk boto3


apt-get update

DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dpkg::Options::=--force-confold \
    -o Dpkg::Options::=--force-confdef \
    --assume-yes --allow-downgrades --allow-remove-essential --allow-change-held-packages \
    upgrade
