"""
This file takes care of parsing signer info and publishing in config for later scan.
"""
# Make Mongo connection
# Query into mongo
# Pull a day's data
# Store the data in the file
# Parse the data and pull classification and signer info
# Based on criteria Put the corrupted one in config if it is not present
# Let the pesigner read from this config and detect the malware


import json
import time
import datetime
from Conn import DataLayer
from File import File

DBNAME = "global_tss_v2"
#COLLNAME = "deepscan_detection_results"
COLLNAME = "deepscan_research_data"
COMMON_NAME = "commonName="

class Engine(object):
    def __init__(self) -> None:
        pass

    def get_and_process_rlabs_data(self):
        try:
            timeNow = time.time()
            timeYesterday = timeNow - 286400
            yesterday = datetime.datetime.fromtimestamp(timeYesterday)
            dbQuery = {"creation_date":{"$gt":yesterday}, "file_type":{"$eq":"application/x-dosexec"},
                       "rlabs.result.tc_report.0.metadata.certificate.signer_info.version":1}
            records = DataLayer.get_document(DBNAME, COLLNAME, dbQuery)
            for record in records:
                self.process_signer_info(record['rlabs']['result']['tc_report'][0])
        except Exception as e:
            print("Exception in querying into mongo: {}".format(e))


    def process_signer_info(self, tc_report_data):
        update_blocklist = True
        try:
            configData = File.read_signer_config()
            if tc_report_data['classification']['classification'] > 3 or tc_report_data['classification']['factor'] > 3:
                serial_number = tc_report_data['metadata']['certificate']['signer_info']['serial_number'].lower()
                common_name = tc_report_data['metadata']['certificate']['signer_info']['issuer']
                for bl in configData.get('blocklist', []):
                    if common_name == (COMMON_NAME + bl.get('common_name', '')) and \
                    (bl.get('serial_number','') in [serial_number, '*']):
                        update_blocklist = False
                if update_blocklist:
                    return self.update_signer_config(configData, common_name, serial_number, tc_report_data['classification']['scan_results'][0]['result'])
            print("Entry present or no signer info present")
        except Exception as e:
            print("Exception in processing signer info: {}".format(e))


    def update_signer_config(self, configData, common_name, serial_number, detection_name):
        try:
            signed_info = {}
            signed_info['common_name'] = common_name.rsplit(COMMON_NAME)[1]
            signed_info['detection_name'] = detection_name
            signed_info['malware_type'] = "Trojan"
            signed_info['serial_number'] = serial_number
            block_list = configData.get('blocklist', [])
            block_list.append(signed_info)
            print(configData)
            File.write_signer_info(configData)
        except Exception as e:
            print("Exception in updating signer info: {}".format(e))


def main():
    signerEngine = Engine()
    signerEngine.get_and_process_rlabs_data()

if __name__ == "__main__":
    main()