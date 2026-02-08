#!/bin/bash

# Declare functions the are used to conditionalize the running of some of the code in setup/*.sh

# Default is that we are running on a host, not in a container, so run
# all code except that which is specific to building an OCI image

function configure_host {
    true
}

function configure_site {
    true
}

function configure_image {
    false
}


# Re-declare functions if process is running in a container runtime,
# and more-specifically as part of an image build

# is process running in a container
if [[ -e /run/.containerenv || -e /run/.dockerenv ]] ; then
    # Skip code that depends on running in a host environment
    function configure_host {
        false
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

        # Skip code that depends on being in a container runtime, i.e. due to 'podman run ...'
        function configure_site {
            false
        }

        # Run image configuration-specific code
        function configure_image {
            true
        }
    else
        # We are a process in a running container, e.g. due to 'podman run ...' or  'docker run ...'

        # Containers set the container env var, so verify we're in a container runtime
        [[ container == "podman" || container == "docker" ]]

        export PRIMARY_HOSTNAME=$(hostname)

        # Run code that depends on being in container runtime
        function configure_site {
            true
        }
    fi
fi
