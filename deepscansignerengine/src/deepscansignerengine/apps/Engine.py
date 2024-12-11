"""
This file takes care of parsing signer info and publishing in config for later scan.
"""


import json
import time
import datetime
from Conn import DataLayer
from File import File

DBNAME = "global_tss_v2"
COLLNAME = "deepscan_detection_results"
COMMON_NAME = "commonName="

class Engine(object):
    def __init__(self):
        pass

    def get_and_process_rlabs_data(self):
        '''
        This method queries into the mongo collection and pulls the required data
        @return: None
        '''
        try:
            timeNow = time.time()
            timeYesterday = timeNow - 286400
            yesterday = datetime.datetime.fromtimestamp(timeYesterday)
            dbQuery = {"creation_date":{"$gt":yesterday}, "file_type":{"$eq":"application/x-dosexec"},
                       "rlabs.result.tc_report.0.metadata.certificate.signer_info.version":1}
            records = DataLayer.get_document(DBNAME, COLLNAME, dbQuery)
            for record in records:
                self.process_signer_info(record['rlabs']['result']['tc_report'][0], record['_id'])
        except Exception as e:
            print("Exception in querying into mongo: {}".format(e))


    def process_signer_info(self, tc_report_data, md5):
        '''
        This method processes the response received from rlabs and find for malicious content
        @param: tc_report_data - tc_report data element consisting of malicious signer info
        @param: md5 - md5 of the scanned file
        @return: None
        '''
        update_blocklist = True
        try:
            configData = File.read_signer_config()
            if tc_report_data['classification']['classification'] >= 3 and tc_report_data['classification']['factor'] >= 2:
                serial_number = tc_report_data['metadata']['certificate']['signer_info']['serial_number'].lower()
                common_name = tc_report_data['metadata']['certificate']['signer_info']['issuer']
                if "countryName" not in common_name:
                    for bl in configData.get('blocklist', []):
                        if common_name == (COMMON_NAME + bl.get('common_name', '')) and \
                        (bl.get('serial_number','') in [serial_number, '*']):
                            update_blocklist = False
                    if update_blocklist:
                        print("Processing for md5: {}".format(md5))
                        return self.update_signer_config(configData, common_name, serial_number, tc_report_data['classification']['scan_results'][0]['result'], md5)
            print("Malicious signer info not found")
        except Exception as e:
            print("Exception in processing signer info: {}".format(e))


    def update_signer_config(self, configData, common_name, serial_number, detection_name, md5):
        '''
        This method updates the local config file with the malicious signer information
        @param: configData - Blocklist config info before update
        @param: common_name - issuer of the certificate
        @param: serial_number - serial_number of the certificate
        @param: detection_name - detection_name of the certificate
        @param: md5 - md5 of the scanned file
        @return: None
        '''
        try:
            signed_info = {}
            signed_info['common_name'] = common_name.rsplit(COMMON_NAME)[1]
            signed_info['detection_name'] = detection_name
            signed_info['malware_type'] = "Trojan"
            signed_info['serial_number'] = serial_number
            block_list = configData.get('blocklist', [])
            block_list.append(signed_info)
            File.write_signer_info(configData)
            print("Signer info updated for md5 : {}, serial no : {}".format(md5, serial_number))
        except Exception as e:
            print("Exception in updating signer info: {}".format(e))


def main():
    signerEngine = Engine()
    signerEngine.get_and_process_rlabs_data()

if __name__ == "__main__":
    main()