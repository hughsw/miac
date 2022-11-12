
##### MIAC_GENERIC_BEGIN

# Ensure the STORAGE_ROOT directory, and STORAGE_USER
#
# Set the directory and all of its parent directories' permissions to world
# readable since it holds files owned by different processes.
mkdir -p $STORAGE_ROOT

f=$STORAGE_ROOT
while [[ $f != / ]]; do
    chmod a+rx $f
    f=$(dirname $f)
done


# If the STORAGE_ROOT is missing the mailinabox.version file that lists a
# migration (schema) number for the files stored there, assume this is a fresh
# installation to that directory and write the file to contain the current
# migration number for this version of Mail-in-a-Box.
if ! id -u $STORAGE_USER >/dev/null 2>&1; then
    useradd $STORAGE_USER
fi

# MIAC migrate/version/state semantics
# MIAC the following is not a migration, it's a code introspection to determine code's version number

if [ ! -f $STORAGE_ROOT/mailinabox.version ]; then
    setup/migrate.py --current > $STORAGE_ROOT/mailinabox.version
    chown $STORAGE_USER:$STORAGE_USER $STORAGE_ROOT/mailinabox.version
fi

##### MIAC_GENERIC_END
