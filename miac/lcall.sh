#!/bin/bash

set -euo pipefail

set -x

#apt-get install -y locales

locale
locale -a
locale-gen en_US.UTF-8
locale -a
export LC_ALL=en_US.UTF-8
