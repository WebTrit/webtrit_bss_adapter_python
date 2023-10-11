import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel, Field
from bss.types import (UserInfo, EndUser, ContactInfo, CDRInfo, 
                       UserCreateResponse,
                       APIAccessErrorCode, FailedAuthCode, UserNotFoundCode, UserAccessErrorCode,
                       RefreshTokenErrorCode,                    
                       safely_extract_scalar_value)
from bss.sessions import SessionStorage, SessionInfo
from bss.adapters.otp import OTPHandler, SampleOTPHandler
from app_config import AppConfig
from report_error import WebTritErrorException
from module_loader import ModuleLoader
from typing import List, Dict, Any, Optional, Callable

class AttrMap(BaseModel):
    """Define how to map the attributes of one data structure
    (e.g. how user data is stored in external system) to the
    naming used in WebTrit.
    
    For example, if the external system uses "login" attribute
    to store the customer's username, and WebTrit uses "user_id",
    then the mapping would be:
    AttrMap(new_key = "user_id", old_key = "login")

    If we need to do some conversion, e.g. strip off the "+" in
    front of a phone number, we can supply the function that will do
    the desired converion via converter parameter:
    AttrMap(new_key = "main", old_key = "phone_num",
        converter = lambda x: x[1:] if x.startswith("+") else x
    """
    new_key: str
    old_key: Optional[str] = None  # if not provided, the old name is used
    converter: Optional[Callable] = None  # custom conversion function

class SessionManagement(ABC):
    """Basic session management on our side."""
    def __init__(self) -> None:
        # this should be overridden in the subclass, otherwise
        # you end up storing sessions only in memory
        self.sessions = SessionStorage()

    def validate_session(self, access_token: str) -> SessionInfo:
        """Validate that the supplied API token is still valid."""

        session = self.sessions.get_session(access_token=access_token)

        if session:
            if not session.still_active():
                # remove it from the DB
                self.sessions.delete_session(
                    access_token=access_token,
                    refresh_token=None # keep the refresh token
                )
                # raise an error
                raise WebTritErrorException(
                    status_code=401,
                    code=APIAccessErrorCode.access_token_expired,
                    error_message=f"Access token {access_token} expired",
                )

            return session

        raise WebTritErrorException(
            status_code=401,
            code=APIAccessErrorCode.access_token_invalid,
            error_message=f"Invalid access token {access_token}",
        )

    def refresh_session(self, refresh_token: str) -> SessionInfo:
        """Extend the API session be exchanging the refresh token for
        a new API access token."""
        session = self.sessions.get_session(refresh_token=refresh_token)
        if not session:
            raise WebTritErrorException(
                status_code=401,
                code=RefreshTokenErrorCode.refresh_token_invalid,
                error_message=f"Invalid refresh token {refresh_token}",
            )

        if not isinstance(session, SessionInfo):
            # accessing some old objects in the DB which do not store refresh token
            # as a separate full object
            raise WebTritErrorException(
                status_code=401,
                code=RefreshTokenErrorCode.refresh_token_invalid,
                error_message=f"Outdated refresh token {refresh_token} - was stored in the old format",
            )
        access_token = safely_extract_scalar_value(session.access_token)        
        if not session.still_active():
            # remove it from the DB
            self.sessions.delete_session(
                access_token=access_token,
                refresh_token=refresh_token 
            )
            # raise an error
            raise WebTritErrorException(
                status_code=401,
                code=RefreshTokenErrorCode.access_token_expired,
                error_message=f"Refresh token {refresh_token} expired",
            )
        # everything is in order, create a new session
        new_session = self.sessions.create_session(UserInfo(
                            user_id=safely_extract_scalar_value(session.user_id)))
        self.sessions.store_session(new_session)
        logging.debug(f"Authenticated user {safely_extract_scalar_value(new_session.user_id)}" +
                      " via refresh token " +
                      f"{refresh_token}, session {safely_extract_scalar_value(new_session.access_token)} created")
        # remove the old session and old refresh token
        self.sessions.delete_session(access_token, refresh_token=refresh_token)
        return new_session

    def close_session(self, access_token: str) -> bool:
        """Close the API session and logout the user."""
        session = self.sessions.get_session(access_token)
        if session:
            return self.sessions.delete_session(access_token)

        raise WebTritErrorException(
            status_code=401,
            code=UserAccessErrorCode.session_not_found,
            error_message=f"Error closing the session {access_token}",
        )

class BSSAdapter(SessionManagement, OTPHandler):
    def __init__(self, config: AppConfig):
        self.config = config

    def initialize(self) -> bool:
        """Initialize some session-related data, e.g. open a connection
        to the database. This can be done after the creation of a new
        object."""
        pass

    # virtual methods - override them in your subclass
    # these two are class methods, so they can be called without
    # creating an object instance
    @classmethod
    def name(cls) -> str:
        """The name of the adapter"""
        raise NotImplementedError("Override this method in your sub-class")

    @classmethod
    def version(cls) -> str:
        """The version"""
        raise NotImplementedError("Override this method in your sub-class")

    # these are regular class methods
    @abstractmethod
    def get_capabilities(self) -> list:
        """Capabilities of your hosted PBX / BSS / your API adapter"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> List[ContactInfo]:
        """List of other extensions in the PBX"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_calls(
        self,
        session: SessionInfo,
        user: UserInfo,
        date_from: datetime = None,
        date_to: datetime = None,
    ) -> List[CDRInfo]:
        """Obtain CDRs (call history) of the user"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_call_recording(
        self, session: SessionInfo, recording_id: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def signup(self, user_data, tenant_id: str = None) -> UserCreateResponse:
        """Create a new user as a part of the sign-up process"""
        raise NotImplementedError("Override this method in your sub-class")

    @classmethod
    def remap_dict(self, mapping: List[AttrMap], data: dict) -> dict:
        """Remap the keys of the dictionary"""
        new_dict = {}
        for x in mapping:
            value = data.get(x.old_key if x.old_key else x.new_key, None)
            new_dict[x.new_key] = value if not x.converter else x.converter(value)
        return new_dict

    @classmethod
    def compose_display_name(cls, first_name: str, last_name: str) -> str:
        """Compose the display name from the first and last name"""
        if first_name and last_name:
            return f"{last_name}, {first_name}"
        return first_name if first_name else last_name
    
    def default_id_if_none(self, tenant_id: str) -> str:
        """Provide a defaut value for tenant ID if none is supplied in HTTP headers"""
        return tenant_id if tenant_id else "default"


class BSSAdapterExternalDB(BSSAdapter, SampleOTPHandler):
    """Supply to WebTrit core information about
    VoIP users (only their SIP credentials) and the list of
    extensions (other users) in the PBX. This typically is
    required when the VoIP system or PBX does not have a proper
    API to retrive the information; so the user data is "replicated"
    into some other DB (e.g. MySQL, MongoDB, Firestore, etc.) so
    it can be retrieved by WebTrit."""

    def __init__(self, config: AppConfig, *args, **kwargs):
        super().__init__(config, *args, **kwargs)
        self.config = config
        # these have to be re-assigned in the sub-class constructor
        self.user_db = None
        self.sessions = None
        self.otp_db = None

    def find_user_by_login(self, user: UserInfo):
        """The same users may use different login IDs, e.g.
        email, phone number or made-up login username.
        By default we assume login is the same as the user_id,
        but you can override this method in your sub-class to
        enable more creative search by various options. """
        # important: need to use user.login here, not user.user_id
        return self.user_db.get(user.login, None)

    def retrieve_user_info(self, user: UserInfo):
        """Get the full user data using user's unique ID - typically user.user_id"""
        return self.user_db.get(user.user_id, None)
        
    def extract_user_id(self, user_data: object) -> str:
        """Extract user_id (unique and unmutable identifier of the user)
        from the data in the DB. Please override it in your sub-class"""
        if hasattr(user_data, "user_id"):
            # we receive a proper dataclass object
            return user_data.user_id
        elif hasattr(user_data, "get"):
            return user_data.get("user_id", None)
        else:
            return None
        
    def verify_password(self, user_data, password: str) -> bool:
        """Verify that the supplied password is correct - please override it
        in your sub-class to perform a proper vertification using the structure
        of your data in the DB"""
        if hasattr(user_data, "password"):
            # we receive a proper dataclass object
            passw_in_db = user_data.password
        elif hasattr(user_data, "get"):
            passw_in_db = user_data.get("password", None)
        else:
            return False
        return passw_in_db == password
    
    def produce_user_object(self, db_data) -> EndUser:
        """Create a user object from the data in the DB"""
        return EndUser(**db_data)

    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and
        produce an API token for further requests."""
        
        user_data = self.find_user_by_login(user)
        if user_data:
            if self.verify_password(user_data, password):
                # everything is in order, create a session
                user.user_id = self.extract_user_id(user_data)
                session = self.sessions.create_session(user)
                self.sessions.store_session(session)
                return session

            raise WebTritErrorException(
                status_code=401,
                code=FailedAuthCode.incorrect_credentials,
                error_message="Invalid password",
            )

        # something is wrong. your code should return a more descriptive
        # error message to simplify the process of fixing the problem
        raise WebTritErrorException(
            status_code=401,
            code=FailedAuthCode.incorrect_credentials,
            error_message="User authentication error",
        )

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user_data = self.retrieve_user_info(user)
        if user_data:
            return self.produce_user_object(user_data)

        # no such session
        raise WebTritErrorException(
            status_code=404,
            code=UserNotFoundCode.user_not_found,
            error_message="User not found"
        )

    # these are the "standard" methods from BSSAdapter you are expected to override
    @classmethod
    def version(cls) -> str:
        """The version"""
        raise NotImplementedError("Override this method in your sub-class")

    @classmethod
    def name(cls) -> str:
        """The name of the adapter"""
        raise NotImplementedError("Override this method in your sub-class")
    
    @abstractmethod
    def get_capabilities(self) -> list:
        """Capabilities of your hosted PBX / BSS / your API adapter"""
        raise NotImplementedError("Override this method in your sub-class")
    
    @abstractmethod
    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> List[ContactInfo]:
        """List of other extensions in the PBX"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_calls(
        self,
        session: SessionInfo,
        user: UserInfo,
        date_from: datetime = None,
        date_to: datetime = None,
    ) -> List[CDRInfo]:
        """Obtain CDRs (call history) of the user"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_call_recording(
        self, session: SessionInfo, recording_id: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        raise NotImplementedError("Override this method in your sub-class")
    
    def signup(self, user_data, tenant_id: str = None) -> UserCreateResponse:
        """Create a new user as a part of the sign-up process"""
        raise NotImplementedError("Override this method in your sub-class")

# initialize BSS Adapter
def initialize_bss_adapter(root_package: str, config: AppConfig) -> BSSAdapter:
    """Create an instance of BSS adapter - of the type specified in the config"""

    bss_module_path = config.get_conf_val("BSS", "Adapter", "Path")
    bss_module_name = config.get_conf_val(
        "BSS", "Adapter", "Module", default="bss.adapters.example"
    )
    bss_class_name = config.get_conf_val(
        "BSS", "Adapter", "Class", default="ExampleBSSAdapter"
    )
    class_ref = ModuleLoader.load_module_and_class(
        bss_module_path, bss_module_name, bss_class_name, root_package
    )
    adapter = class_ref(config=config)
    adapter.initialize()
    logging.info(f"Initialized BSS adapter: {bss_class_name} v{adapter.version()}")
    return adapter
