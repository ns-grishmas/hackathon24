#!/bin/bash

# Execute the script to parse through responses received from Rlabs in last few days
# This will also publish the config file which is meant to be updated in Netskope Advanced AV's config
python apps/Engine.py
echo "The local config got updated"

# Pushing config to Netskope Advanced AV pod  
curl -XPUT -H 'Content-Type: text/plain' --data-binary '@resources/pe_allowlist_blocklist_config.json'   http://cfgpusher01:8887/file/opt/ns/cfg/deepscan/NSKP-OSMTP/pe_allowlist_blocklist_config.json