#!/bin/bash

if [ $(which apt-get) ];
then
    sudo apt-get update
    PKG_MANAGER="apt-get"
    PKGS="python python-dev git curl"
else
    PKG_MANAGER="yum"
    PKGS="python python-devel git curl"
fi

sudo $PKG_MANAGER -y install $PKGS

if [ $(which pip) ];
then
    echo ''
else
    curl -L "https://bootstrap.pypa.io/get-pip.py" > get_pip.py
    sudo python get_pip.py
    rm get_pip.py
    sudo pip install gitpython
fi
