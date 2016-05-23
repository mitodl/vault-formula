#!/bin/bash

if [[ -z $(which pip) ]]
then
    sudo salt-call --local pkg.install python-pip
fi
if [[ -z $(which testinfra) ]]
then
    sudo pip install testinfra
fi
if [ "$(ls /vagrant)" ]
then
    SRCDIR=/vagrant
else
    SRCDIR=/home/vagrant/sync
fi
sudo rm -rf $SRCDIR/tests/__pycache__
testinfra $SRCDIR/tests
