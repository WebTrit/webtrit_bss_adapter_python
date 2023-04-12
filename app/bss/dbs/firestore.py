from bss.dbs import TiedKeyValue
from google.cloud import firestore
from google.oauth2 import service_account
#from firebase_admin import credentials, firestore
import os
import json
import pickle

class FirestoreKeyValue(TiedKeyValue):
    """Access user data stored in Firestore"""

    def __init__(self,
                credentials_file: str,
                collection_name: str):
        """Initialize the database connection"""
        cred = self.__credentials__(credentials_file)
        self.db = firestore.Client(credentials=cred)
        self.collection = collection_name

    def __credentials__(self, credentials_file: str):
        """Get the credentials for the database"""
        if credentials_file is None:
            # no specific credentials file was provided, use
            # env variable if available
            if (env_var := os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', None)):
                # we are running in the cloud
                credentials_file = env_var
        return service_account.Credentials.from_service_account_file(credentials_file)

    def __pack2store__(self, value):
        """Pack the data into a format suitable for storage"""
        if hasattr(value, '__dict__'):
            data = {
                'object_type': type(value).__name__, 
                'object_data': pickle.dumps(value)
            }
        else:
            data = value
        return data
    
    def __unpack_from_store__(self, value):
        """Unpack the data from the storage format"""
        if isinstance(value, dict) and 'object_type' in value:
            obj_type = value['object_type']
            obj_data = value['object_data']
            if obj_type == 'bytes':
                value = obj_data
            else:
                value = pickle.loads(obj_data)
        return value
    
    def __getitem_doc__(self, key):
        doc_ref = self.db.collection(self.collection).document(key)
        doc = doc_ref.get()
        return doc
    
    def __getitem__(self, key):
        doc = self.__getitem_doc__(key)
        if doc.exists:
            return self.__unpack_from_store__(doc.to_dict())
        
        raise KeyError(key)
        
    def get(self, key: str, *args):
        """Get the data from the database"""
        doc = self.__getitem_doc__(key)
        if doc.exists:
            return self.__unpack_from_store__(doc.to_dict())

        if args:
            return args[0] 
        else:
            raise KeyError(key)

    def __contains__(self, key):
        doc = self.__getitem_doc__(key)
        return True if doc.exists else False
    
    def __setitem__(self, key, value):
        """Store the data in the database"""
        doc_ref = self.db.collection(self.collection).document(key)
        # TODO: analyze the result
        result = doc_ref.set(self.__pack2store__(value))
        return value
    
    def __delitem__(self, key):
        doc_ref = self.db.collection(self.collection).document(key)
        if doc_ref:
            doc_ref.delete()

    def pop(self, key, *args):
        doc = self.__getitem_doc__(key)
        
        if doc.exists: 
            ret_val = doc.to_dict()
        elif args:
            ret_val = args[0]
        else:
            raise KeyError(key)
        self.__delitem__(key)
        return ret_val
