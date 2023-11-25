# MIAC: MOOT

source /home/user-data/miac-env.sh
source miac/miac-setup-vars.sh


######################################################################
#
# system.sh
#
echo MIAC MOOT system.sh

# MIAC stages sequencing means this block is moot

# This is supposedly sufficient. But because we're not sure if hardware entropy
# is really any good on virtualized systems, we'll also seed from Ubuntu's
# pollinate servers:
# Note: pollinate requires /dev/log which implies systemd is running...
 pollinate  -q -r


# MIAC ssl code is run in an ephemeral container, so no point in updating system files.
# MIAC Instead we make a key that is stored in $STORAGE_ROOT/backup, see management.sh

# We need an ssh key to store backups via rsync, if it doesn't exist create one
if [ ! -f /root/.ssh/id_rsa_miab ]; then
	echo 'Creating SSH key for backup…'
	ssh-keygen -t rsa -b 2048 -a 100 -f /root/.ssh/id_rsa_miab -N '' -q
fi



######################################################################
#
# mail-postfix.sh
#
echo MIAC MOOT mail-postfix.sh

        # Stop the service
        service postgrey stop


# ensure success code when this script is sourced
/bin/true

