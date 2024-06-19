#!/bin/bash

NP2_MODULE_DIR=/usr/local/share/yang/modules/netopeer2/ NP2_MODULE_PERMS=600 /usr/local/share/netopeer2/setup.sh
/usr/local/share/netopeer2/merge_hostkey.sh 
/usr/local/share/netopeer2/merge_config.sh 
netopeer2-server -d -v1 -t60
