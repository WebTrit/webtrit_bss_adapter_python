from bss.dbs import TiedKeyValue
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
#from google.oauth2 import service_account
import json
import logging
# from firebase_admin import credentials, firestore
from bss.dbs.serializer import Serializer
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union

class QueryFilter(BaseModel):
    field: str = Field( description="Field name", example="tenant_id")
    value: str = Field( description="Field value", example="1234")
    op: Optional[str] = Field( description="Comparison operator (== by default)",
                                default=u"==", example="!=")


class FirestoreKeyValue(TiedKeyValue):
    """Access user data stored in Firestore"""

    def __init__(self, collection_name: str):
        """Initialize the database connection"""
        # cred = self.__credentials__(credentials_file)
        # default mode - it will use GOOGLE_APPLICATION_CREDENTIALS env
        # var whan running locally; in cloud run it should use ADC
        self.db = firestore.Client()
        self.collection = collection_name
    # apparently it is better to let the client library to extract credentials
    # this way we can use ADC in cloud run and a file locally
    # def __credentials__(self, credentials_file: str):
    #     """Get the credentials for the database"""
    #     if credentials_file is None:
    #         # no specific credentials file was provided, use
    #         # env variable if available
    #         if env_var := os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON", None):
    #             # credentials provided via env var - default mode for cloud run
    #             credentials_dict = json.loads(env_var)
    #             return service_account.Credentials.from_service_account_info(credentials_dict)
            
    #         if env_var := os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", None):
    #             # we are running in the cloud
    #             credentials_file = env_var
    #     return service_account.Credentials.from_service_account_file(credentials_file)

    def __pack2store__(self, value):
        """Pack the data into a format suitable for storage"""

        return Serializer.pack(value)

    def __unpack_from_store__(self, value):
        """Unpack the data from the storage format"""
        return Serializer.unpack(value)

    def __docref__(self, key):
        """Provide a references to the document which corresponds to the key"""
        return self.db.collection(self.collection).document(key)
    
    def __getitem_doc__(self, key):
        doc_ref = self.__docref__(key)
        doc = doc_ref.get()
        return doc

    def __getitem__(self, key):
        doc = self.__getitem_doc__(key)
        if doc.exists:
            return self.__unpack_from_store__(doc.to_dict())

        raise KeyError(key)
        
    def get(self, key: str, *args):
        """Get the data from the database, return default if not found"""
        try:
            return self.__getitem__(key)
        except KeyError:
            if args:
                return args[0]
            raise KeyError(key)


    def __contains__(self, key):
        doc = self.__getitem_doc__(key)
        return True if doc.exists else False

    def __setitem__(self, key, value):
        """Store the data in the database"""
        doc_ref = self.__docref__(key)
        # TODO: analyze the result
        result = doc_ref.set(self.__pack2store__(value))
        return value

    def __delitem__(self, key):
        doc_ref = self.__docref__(key)
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

    def __iter__(self):
        """Iterate over the keys"""
        docs = self.db.collection(self.collection).stream()
        for doc in docs:
            yield doc.id

    def keys(self):
        """Iterate over the keys"""
        return iter(self)

    def search(self, *args) -> list:
        """Search for an object based on criteria.
        
        Returns a list of objects which match the criteria or an empty list"""
        query = self.db.collection(self.collection)
        logging.debug(f"Searching in {self.collection}")
        for f in args:
            if not isinstance(f, QueryFilter):
                raise TypeError(f"Search parameter must be a QueryFilter object, got {f}")
            filter = FieldFilter(field_path = f.field,
                                        op_string = u"==" if not f.op else f.op,
                                        value = f.value)
            logging.debug(f"Adding filter {f}")
            query = query.where(filter=filter)
    
        # Get the first matching document
        docs = query.get()
        if isinstance(docs, list):
            if (x := len(docs)) > 0:
                logging.debug(f"{x} items returned by the search")
                return [ self.__unpack_from_store__(x.to_dict()) for x in docs ]
            
        elif docs:
            # still cannot figure out when a single object and when a list
            # is returned
            logging.debug("A single item returned by the search")
            return [ self.__unpack_from_store__(docs.to_dict()) ]
        
        logging.debug("No items returned by the search")
        return []
