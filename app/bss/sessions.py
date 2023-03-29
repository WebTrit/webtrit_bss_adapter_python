import threading
from datetime import datetime, timedelta
import shelve
import logging
from app_config import AppConfig
from bss.models import SessionApprovedResponseSchema

class SessionInfo(SessionApprovedResponseSchema):
    """Info about a session, initiated by WebTrit core on behalf of user"""

    def still_active(self, timestamp=datetime.now()) -> bool:
        """Check whether the session has not yet expired"""

        return self.expires_at > timestamp
    
class SessionStorage:
    """A class that provides access to stored session data (which can
    be stored in some SQL/no-SQL database, external REST services, etc.)"""
    session_db_lock = threading.Lock()

    def __init__(self, config: AppConfig):
        """Initialize the object using the provided configuration"""
        self.config = config
        # your sub-class should initialize the storage and assign it to self.sessions
        self.sessions = None
        # for simple in-memory storage or file-based storage it is better
        # to ensure only one thread will do a modification at any time
        self.get_lock_when_changing = True

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
            return self.sessions.get(refr_id, None)
        return self.sessions.get(access_token, None)

    def __store_session(self, session: SessionInfo):
        self.sessions[session.access_token] = session
        # also add the possibility to find the session by its refresh token
        refresh_token = self.__refresh_token_index(session.refresh_token)
        self.sessions[refresh_token] = session

    def store_session(self, session: SessionInfo):
        """Store a session in the database"""

        if self.get_lock_when_changing:
            with self.session_db_lock:
                self.__store_session(session)
        else:
            self.__store_session(session)

    def __delete_session(self, access_token: str, refresh_token: str = None) -> bool:
        """Remove a session from the database"""

        if refresh_token:
            self.sessions.pop(refresh_token, None)
        session = self.sessions.pop(access_token, None)

        return True if session else False
    
    def delete_session(self, access_token: str, refresh_token: str = None) -> bool:
        """Remove a session from the database"""

        if self.get_lock_when_changing:
            with self.session_db_lock:
                return self.__delete_session(access_token, refresh_token)
        else:  
            return self.__delete_session(access_token, refresh_token)


class FileSessionStorage(SessionStorage):
    """Store sessions in a class variable. Suitable only
    for demo / development. Implement a real persistent
    session storage for your application."""
    def __init__(self, config: AppConfig):
        super().__init__(config)
        # to make the sessions survive a restart of a container - 
        # ensure that /var/db/ (or whichever
        # location you choose) is mounted as a volume to the container
        file_name = config.get_conf_val('Sessions', 'StorageFile',
                            default = '/var/db/sessions.db')
        logging.debug(f"Using file {file_name} for session storage")
        self.sessions = shelve.open(file_name)
