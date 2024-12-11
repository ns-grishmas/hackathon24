"""
Contains mongo connection details
"""

import pymongo
import time
import datetime

class DataLayer(object):
    def __init__(self):
        pass

    @staticmethod
    def get_mongo_client():
        try:
            return pymongo.MongoClient("mongodb://mtp_admin:S3cur3Th3Cl0ud@10.136.127.9:27017/admin")
        except Exception as e:
            print("Exception in creating mongo client: {}".format(e))

    @staticmethod
    def get_mongo_db(dbName):
        try:
            return DataLayer.get_mongo_client()[dbName]
        except Exception as e:
            print("Exception in connecting to db: {}, exception {}".format(dbName, e))

    @staticmethod
    def get_mongo_collection(dbName, collectionName):
        try:
            database = DataLayer.get_mongo_db(dbName)
            return database[collectionName]
        except Exception as e:
            print("Exception in connecting to collection: {}, db: {}, exception {}".format(collectionName, dbName, e))

    @staticmethod
    def get_document(dbName, collectionName, query):
        try:
            cursor = DataLayer.get_mongo_collection(dbName, collectionName).find(query)
            return cursor
        except Exception as e:
            print("Exception in querying for document in Mongo: {}".format(e))