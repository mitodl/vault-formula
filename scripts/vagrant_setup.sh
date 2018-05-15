#!/bin/bash

sudo mkdir -p /srv/salt
sudo mkdir -p /srv/pillar
sudo cp /srv/salt/pillar.example /srv/pillar/pillar.sls
echo "\
base:
  '*':
    - pillar" | sudo tee /srv/pillar/top.sls
sudo cp /srv/salt/salt-top.example /srv/salt/top.sls
