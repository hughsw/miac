#!/bin/bash

# Determine if process is running on a stand-alone host, as part of an
# image build, or in a container runtime

# is process running in a container
if [[ -e /run/.containerenv || -e /run/.dockerenv ]] ; then
    # is it part of an image building 'RUN cmd ...'
    if grep -e '^/bin/sh\>' /proc/1/cmdline ; then
        # RUN (appears to) always use '/bin/sh' '-c' in process 1
        # We are in a container, a step of building an image, i.e. part of a Dockerfile 'RUN cmd ...'

        # Skip code that depends on running in a host environment
        function configure_host {
            false
        }

        # Skip code that depends on being in a container runtime, i.e. due to 'podman run ...'
        function configure_site {
            false
        }

        #ln -sf setup/configs/build-image.sh setup/setup-config.sh
    else
        # containers set the container env var, so verify we're in a container runtime
        [[ container == "podman" || container == "docker" ]]

        # We are a process in a running container, e.g. due to 'podman run ...' or  'docker run ...'

        # Skip code that depends on running on a host environment (bare metal, VPS instance, etc)
        function configure_host {
            false
        }

        # Run code that depends on being in container runtime
        function configure_site {
            true
        }

        #ln -sf setup/configs/run-container.sh setup/setup-config.sh
    fi
else
    # We are running on a host, not in a container, so run all code
    function configure_host {
        true
    }

    function configure_site {
        true
    }

    #ln -sf setup/configs/host.sh setup/setup-config.sh
fi
