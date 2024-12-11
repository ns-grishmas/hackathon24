"""
This file reads from json
"""

import json

SIGNER_CONFIG_FILE = 'resources/pe_allowlist_blocklist_config.json'

class File(object):
    def __init__(self):
        pass

    @staticmethod
    def read_signer_config():
        # Open and read the JSON file
        with open(SIGNER_CONFIG_FILE, 'r') as file:
            data = json.load(file)
        return data

    @staticmethod
    def write_signer_info(config_data):
        # Open and write the JSON into file
        with open(SIGNER_CONFIG_FILE, 'w') as file:
            json.dump(config_data, file)