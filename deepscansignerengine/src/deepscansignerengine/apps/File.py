"""
This file reads from json
"""

import json

COMMON_NAME = "commonName="
SIGNER_CONFIG_FILE = '../resources/signer_config.json'

class File(object):
    def __init__(self):
        pass

    @staticmethod
    def read_file():
        # Open and read the JSON file
        with open('../resources/sample_detected_file.json', 'r') as file:
            data = json.load(file)
        return data

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