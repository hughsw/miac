#!/bin/bash


# Create the STORAGE_USER and STORAGE_ROOT directory if they don't already exist.
#
# Set the directory and all of its parent directories' permissions to world
# readable since it holds files owned by different processes.
#
# If the STORAGE_ROOT is missing the mailinabox.version file that lists a
# migration (schema) number for the files stored there, assume this is a fresh
# installation to that directory and write the file to contain the current
# migration number for this version of Mail-in-a-Box.
if ! id -u $STORAGE_USER >/dev/null 2>&1; then
    useradd -m $STORAGE_USER
fi
if [ ! -d $STORAGE_ROOT ]; then
    mkdir -p $STORAGE_ROOT
fi

f=$STORAGE_ROOT
while [[ $f != / ]]; do chmod a+rx "$f"; f=$(dirname "$f"); done;

if [ ! -f $STORAGE_ROOT/mailinabox.version ]; then
    setup/migrate.py --current > $STORAGE_ROOT/mailinabox.version
    chown $STORAGE_USER:$STORAGE_USER $STORAGE_ROOT/mailinabox.version
fi
