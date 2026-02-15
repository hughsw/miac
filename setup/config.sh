#!/bin/bash

# Declare functions the are used to conditionalize the running of some of the code in setup/*.sh

# Default is that we are running on a host, not in a container, so run
# all code

# use for code that should only be run on a host, never in a container
function host_code {
    true
}
# use for code that should only be run in a container, never on a host
function container_code {
    false
}

# use for code that is specific to a configured site (has a hostname, encryption keys, databases, etc)
function site_code {
    true
}


# Re-declare functions if process is running in a container runtime,
# and more-specifically as part of an image build

# is process running in a container
if [[ -e /run/.containerenv || -e /run/.dockerenv ]] ; then
    # In any container, skip code that depends on running in a host environment
    function host_code {
        false
    }
    function container_code {
        true
    }

    # Env settings for container setup

    #export DISABLE_FIREWALL=1
    export NONINTERACTIVE=1
    export SKIP_NETWORK_CHECKS=1

    export PUBLIC_IP=auto
    export PUBLIC_IPV6=auto

    export STORAGE_USER="miac"
    export STORAGE_ROOT="/home/miac-data"

    #export PRIMARY_HOSTNAME=$(hostname)

    # Is it part of an image building 'RUN cmd ...'
    # Dockerfile RUN (appears to) always use '/bin/sh -c '...' in process 1
    # The cmdline fiile has nulls between the exec arguments
    if grep --binary-files=binary -e '^/bin/sh\>' /proc/1/cmdline ; then
        # We are building an image, so no site-specific logic, but do the image-building-specific logic

        # Skip code that depends on being in a site-specific container runtime, i.e. due to 'podman run ...'
        function site_code {
            false
        }
    else
        # We are a process in a running container, e.g. due to 'podman run ...' or  'docker run ...'

        # Containers set the container env var, so verify we're in a container runtime
        [[ "$container" == "podman" || "$container" == "docker" ]]

        export PRIMARY_HOSTNAME=$(hostname)
    fi
fi
