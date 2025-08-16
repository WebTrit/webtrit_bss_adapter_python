from datetime import datetime, timedelta
import logging
import uuid
from module_loader import ModuleLoader
import bss.dbs
from bss.dbs import FileStoredKeyValue, TiedKeyValue
from bss.dbs.firestore import FirestoreKeyValue
from bss.types import SessionInfo, UserInfo, safely_extract_scalar_value
from abc import ABC, abstractmethod
from app_config import AppConfig

config = AppConfig()

class SessionDBInit(ABC):
    """Create a proper storage object by extract the required config
        options (e.g. filename or Firestore collection name) and passing
        them to the constructor."""
    def __init__(self, config: AppConfig):
        self.config = config

    @abstractmethod
    def extract_config_values(self) -> dict:
        """Process the config and return the values to be passed to
        the constructor of a class derived from bss.dbs.TiedKeyValue"""
        pass

    @abstractmethod
    def instantiate_storage(self) -> TiedKeyValue:
        """Create an object for storing the session data"""
        pass
    
class SessionsInFile(SessionDBInit):
    """Store session data in a file - for debugging purposes only"""
    def extract_config_values(self) -> dict:
        """Process the config and return the values to be passed to
        the constructor of a class derived from bss.dbs.TiedKeyValue"""
        file_name = config.get_conf_val(
            "Sessions", "Storage", "FileName", default="/var/db/sessions.db"
        )
        return dict( file_name = file_name)

    def instantiate_storage(self) -> TiedKeyValue:
        """Create an object for storing the session data"""
        params = self.extract_config_values()
        return FileStoredKeyValue(**params)
   
class SessionsInFirestore(SessionDBInit):
    """Store session data in a Firestore collection - suitable for production"""
    def extract_config_values(self) -> dict:
        """Process the config and return the values to be passed to
        the constructor of a class derived from bss.dbs.TiedKeyValue"""
        collection_name = config.get_conf_val(
            "Sessions", "Storage", "Firestore", default="Sessions"
        )
        return dict( collection_name = collection_name)

    def instantiate_storage(self) -> FirestoreKeyValue:
        """Create an object for storing the session data"""
        params = self.extract_config_values()
        return FirestoreKeyValue(**params)

class SessionStorage:
    """A class that provides access to stored session data (which can
    be stored in some SQL/no-SQL database, external REST services, etc.)"""

    # default time (in hours) after which the session expires, 1 day by default
    SESSION_EXPIRATION = int(config.get_conf_val(
        "Sessions", "Storage", "Expiration",
        default = 24
    ))
    # default time (in hours) during which a refresh token is valid and can be exchanged
    # to a new access token, 365 days by default
    REFRESH_TOKEN_EXPIRATION = int(config.get_conf_val(
        "Sessions", "Refresh", "Expiration",
        default = 24 * 365
    )) 

    def __init__(self, session_db=None):
        """Initialize the object using the provided object
        for storing the sessions"""
        self.session_db = session_db if session_db is not None else TiedKeyValue()

    def __refresh_token_index(self, id: str) -> str:
        """Change the value of refresh token so it still will
        be unique, but cannot match any of the access tokens."""

        return "R" + safely_extract_scalar_value(id)

    def generate_id(self) -> str:
        """Generate a new unique ID for the session"""
        return str(uuid.uuid1()).replace("-", "") + str(uuid.uuid4()).replace("-", "")
    
    def get_session(
        self, access_token: str = "", refresh_token: str = None
    ) -> SessionInfo:
        """Retrieve a session"""

        if refresh_token:
            # search by the refresh token
            refr_id = self.__refresh_token_index(refresh_token)
            return self.session_db.get(refr_id, None)

        return self.session_db.get(access_token, None)

    def create_session(self, user: UserInfo) -> SessionInfo:
        """Create a new session object for the user"""
        expiration = datetime.now() + timedelta(hours=self.SESSION_EXPIRATION)
        expiration = expiration.replace(microsecond=0)
        token = self.generate_id()
        session = SessionInfo(
            user_id=user.user_id,
            access_token=token,
            refresh_token=self.generate_id(),
            expires_at=expiration,
            document_ttl=expiration + timedelta(minutes=5)
        )
        logging.debug(f"Created new session with token {token} expiring at " +
                      expiration.isoformat())
        return session

    def __store_session(self, session: SessionInfo):
        access_token = safely_extract_scalar_value(session.access_token)
        self.session_db[access_token] = session
        # also add the possibility to find the session by its refresh token
        r_session = session.copy()
        # why was it created?
        # r_session.long_life_refresh = True
        r_session.expires_at = datetime.now() + timedelta(hours=self.REFRESH_TOKEN_EXPIRATION)
        refresh_token_index = self.__refresh_token_index(session.refresh_token)
        self.session_db[refresh_token_index] = r_session

    def store_session(self, session: SessionInfo):
        """Store a session in the database"""
        self.__store_session(session)

    def __delete_session(self, token: str) -> bool:
        """Remove a session from the database"""

        session = self.session_db.pop(token, None)

        return True if session else False

    def delete_session(self, access_token: str, refresh_token: str = None) -> bool:
        """Remove a session from the database"""
        
        if refresh_token:
            logging.debug(f"Removing session with refresh token {refresh_token}")
            self.__delete_session(self.__refresh_token_index(refresh_token))
        logging.debug(f"Removing session with token {access_token}")
        return self.__delete_session(access_token)

def configure_session_storage(config):
    """Create a proper session storage object based on the configuration"""

    module_name = config.get_conf_val(
        "Sessions", "Storage", "Module", default="bss.sessions"
    )
    class_name = config.get_conf_val(
        "Sessions", "Storage", "Class", default="SessionsInFile"
    )

    logging.debug(f"Using {class_name} for session storage")
    storage_creator = ModuleLoader.load_module_and_class(
        module_path=None,
        module_name=module_name,
        class_name=class_name,
        root_package=bss.sessions.__name__,
    )
    try:
        storage = storage_creator(config=config)
        session_db = storage.instantiate_storage()
    except Exception as e:
        logging.error(f"Failed to create the session storage object {e}")
        raise e
    return SessionStorage(session_db=session_db)
