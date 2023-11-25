#!/bin/bash

set -euo pipefail

set -x

# Add some third-party repositories
apt-get install -y software-properties-common
add-apt-repository -y universe
add-apt-repository -y ppa:duplicity-team/duplicity-release-git
add-apt-repository -y ppa:ondrej/php

apt-get update

