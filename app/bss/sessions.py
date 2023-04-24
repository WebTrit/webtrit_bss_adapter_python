from datetime import datetime, timedelta
import logging
import uuid
from module_loader import ModuleLoader
import bss.dbs
from bss.dbs import (FileStoredKeyValue, TiedKeyValue)
from bss.types import (SessionInfo, UserInfo)
    
class SessionStorage:
    """A class that provides access to stored session data (which can
    be stored in some SQL/no-SQL database, external REST services, etc.)"""
    SESSION_EXPIRATION = 1

    def __init__(self, session_db = None):
        """Initialize the object using the provided object
        for storing the sessions"""
        self.session_db = session_db if session_db else TiedKeyValue()

    def __refresh_token_index(self, id: str) -> str:
        """Change the value of refresh token so it still will
        be unique, but cannot match any of the access tokens."""
        if hasattr(id, "__root__"):
            id = id.__root__
        return "R" + id

    def get_session(self, access_token="", refresh_token: str = None) -> SessionInfo:
        """Retrieve a session"""

        if refresh_token:
            refr_id = self.__refresh_token_index(refresh_token)
            ref = self.session_db.get(refr_id, None)
            if isinstance(ref, dict) and 'access_token' in ref:
                access_token = ref['access_token']
        return self.session_db.get(access_token, None)

    def create_session(self, user: UserInfo) -> SessionInfo:
        """Create a new session object for the user"""
        expiration = datetime.now() + timedelta(days=self.SESSION_EXPIRATION) 
        expiration = expiration.replace(microsecond=0)
        session = SessionInfo(
            user_id=user.user_id,
            access_token=str(uuid.uuid1()),
            refresh_token=str(uuid.uuid1()),
            expires_at=expiration,
        )

        return session
    
    def __store_session(self, session: SessionInfo):
        self.session_db[session.access_token] = session
        # also add the possibility to find the session by its refresh token
        refresh_token = self.__refresh_token_index(session.refresh_token)
        # store a reference to the session, do not copy the object
        self.session_db[refresh_token] = { 
            'type': 'reference',
            'access_token': session.access_token
            }

    def store_session(self, session: SessionInfo):
        """Store a session in the database"""
        self.__store_session(session)

    def __delete_session(self, access_token: str, refresh_token: str = None) -> bool:
        """Remove a session from the database"""

        if refresh_token:
            del self.session_db[refresh_token]
        session = self.session_db.pop(access_token, None)

        return True if session else False
    
    def delete_session(self, access_token: str, refresh_token: str = None) -> bool:
        """Remove a session from the database"""

        return self.__delete_session(access_token, refresh_token)

def configure_session_storage(config):
    """Create a proper session storage object based on the configuration"""

    # TODO: allow dynamic selection of the storage module
    module_name = config.get_conf_val('Sessions', 'Storage', 'Module',
                        default = 'bss.dbs')
    class_name = config.get_conf_val('Sessions', 'Storage', 'Class',
                        default = 'FileStoredKeyValue')
    # storage_module = config.get_conf_val('Sessions', 'StorageModule', default = 'FileStoredKeyValue')
    # store sessions in a local file, to make the sessions survive
    # a restart of a container - ensure that /var/db/ (or whichever
    # location you choose) is mounted as a volume to the container
    # TODO: the parameters for the session storage should be defined in config 
    file_name = config.get_conf_val('Sessions', 'Storage', 'FileName',
                                    default = '/var/db/sessions.db')

    
    logging.debug(f"Using file {file_name} for session storage")
    storage_creator = ModuleLoader.load_module_and_class(module_path=None,
                                                 module_name=module_name,
                                                 class_name=class_name,
                                                 root_package=bss.dbs.__name__)
    storage = storage_creator(file_name = file_name)
    return SessionStorage(session_db = storage)

# class FileSessionStorage(SessionStorage):
#     """Store sessions in local file. Suitable only
#     for demo / development. Implement a real persistent & scalable
#     session storage for your application, or use a class like
#     FirestoreSessionStorage below."""
#     def __init__(self, file_name):
#         super().__init__(FileStoredKeyValue(file_name))



