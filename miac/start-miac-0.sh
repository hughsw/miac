#!/bin/bash

# Check system setup: Are we running as root on Ubuntu 18.04 on a
# machine with enough memory? Is /tmp mounted with exec.
# If not, this shows an error and exits.
source setup/preflight.sh

# Set strict, Load functions
source setup/functions.sh 
# Export some locale envs
source setup/locale.sh

# Migration and establish DEFAULT_* envs, or FIRST_TIME_SETUP
source setup/migrate.sh

# Create /usr/local/bin/mailinabox
source setup/mailinabox-bin.sh

# PITA $(git describe) complains:
#   fatal: detected dubious ownership in repository at '/home/miac/mailinabox'
#   To add an exception for this directory, call:
#
#	git config --global --add safe.directory /home/miac/mailinabox
#ls -la
#git config --global --add safe.directory /home/miac/mailinabox

# Ask the user for the PRIMARY_HOSTNAME, PUBLIC_IP, and PUBLIC_IPV6,
# if values have not already been set in environment variables. When running
# non-interactively, be sure to set values for all! Also sets STORAGE_USER and
# STORAGE_ROOT.
source setup/questions.sh

# Run some network checks to make sure setup on this machine makes sense
source setup/network-checks.sh

# Ensure user and storage directories, and current migration version
source setup/user-storage.sh

# Save global envs in /etc/mailinabox.conf
source setup/mailinabox-conf.sh

true
