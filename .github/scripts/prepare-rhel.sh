#!/bin/bash

set -euo pipefail

# Colors
CGREEN='\033[0;32m'
CRED='\033[0;31m'
CEND='\033[0m'

echo -ne 'Preparing             [..]\r'

if {
    dnf update -qy
    dnf install -qy epel-release
    /usr/bin/crb enable
    dnf update -qy
    dnf groupinstall -qy 'Development Tools'
    dnf install -qy rpmautospec rpmdevtools
} >> /tmp/dependencies.log 2>&1; then
    # Set up rpmbuild tree and move sources
    rpmdev-setuptree
    mv rpm/anti_ddos_challenge.spec ~/rpmbuild/SPECS/
    cp LICENSE README.md lua/anti_ddos_challenge.lua ~/rpmbuild/SOURCES/
    echo -ne "Preparing done    [${CGREEN}OK${CEND}]\n"
else
    echo -e "Prepare failed     [${CRED}FAIL${CEND}]"
    echo "Please see /tmp/dependencies.log"
    cat /tmp/dependencies.log
    exit 1
fi
