import os
import importlib

from datetime import datetime
from abc import ABC, abstractmethod
from bss.models import (
    # ContactsResponseSchema,
    # HistoryResponseSchema,
    SessionApprovedResponseSchema,
    # SigninRequestSchema,
    # OtpCreateRequestSchema,
    OtpCreateResponseSchema,
    OtpVerifyRequestSchema,
    # SessionApprovedResponseSchema,
    # SystemInfoResponseSchema,
    # UserInfoResponseSchema,
    # SupportedEnum,
)

# for now these are just "clones" but we may extend them in the future
# plus we do not want to depend on the names of the objects in the schema too much
# so use these in your code instead of the schema objects
from bss.models import UserInfoResponseSchema as EndUser
from bss.models import ContactsResponseSchema as Contacts
from bss.models import ContactInfoSchema as ContactInfo
from bss.models import HistoryResponseSchema as Calls
from bss.models import ErrorSchema as ErrorMsg
from bss.models import SupportedEnum as Capabilities

from bss.sessions import SessionStorage, SessionInfo
from app_config import AppConfig
from report_error import WebTritErrorException




class BSSConnector(ABC):
    def __init__(self, config: AppConfig):
        self.config = config
        self.storage = SessionStorage(config)

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
    def authenticate(self, user_id: str, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def generate_otp(self, user_id: str) -> OtpCreateResponseSchema:
        """Request that a remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def validate_otp(self, otp: OtpVerifyRequestSchema) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""
        raise NotImplementedError("Override this method in your sub-class")

    def validate_session(self, access_token: str) -> SessionInfo:
        """Validate that the supplied API token is still valid."""

        session = self.storage.get_session(access_token=access_token)

        if session:
            if not session.still_active():
                # remove it from the DB
                self.storage.delete_session(
                    access_token=access_token, refresh_token=session.refresh_token
                )
                # raise an error
                raise WebTritErrorException(
                    status_code=401,
                    code=42,
                    error_message="Access token expired",
                )

            return session

        raise WebTritErrorException(
            status_code=401,
            code=42,
            error_message="Invalid access token",
        )

    def refresh_session(self, user_id: str, refresh_token: str) -> SessionInfo:
        """Extend the API session be exchanging the refresh token for
        a new API access token."""
        session = self.storage.get_session(refresh_token=refresh_token)
        if not session:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid refresh token",
            )
        # everything is in order, create a new session
        session = self.create_session(user_id)
        self.storage.store_session(session)
        return session

    def close_session(self, access_token: str) -> bool:
        """Close the API session and logout the user."""
        session = self.storage.get_session(access_token)
        if session:
            return self.storage.delete_session(access_token)

        raise WebTritErrorException(
            status_code=401,
            code=42,
            error_message="Error closing the session",
        )

    @abstractmethod
    def retrieve_user(self, session: SessionInfo, user_id: str) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_contacts(self, session: SessionInfo, user_id: str) -> Contacts:
        """List of other extensions in the PBX"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_calls(
        self,
        session: SessionInfo,
        user_id: str,
        page: None,
        items_per_page: None,
        date_from: None,
        date_to: None,
    ) -> Calls:
        """Obtain CDRs (call history) of the user"""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        raise NotImplementedError("Override this method in your sub-class")


# initialize BSS connector
def initialize_bss_connector(root_package, config) -> BSSConnector:
    """Create an instance of BSS connector - of the type specified in the config"""
    bss_module_path = config.get_conf_val(
        "BSS", "Connector", "Path", default="bss.connectors"
    )
    bss_module_name = config.get_conf_val(
 #       "BSS", "Connector", "Module", default="bss.connectors.freepbx"
         "BSS", "Connector", "Module", default="bss.connectors.example"
#                "BSS", "Connector", "Module", default="example"
    )
    bss_class_name = config.get_conf_val(
        "BSS", "Connector", "Class", default="ExampleBSSConnector"       
#        "BSS", "Connector", "Class", default="ExampleBSSConnector"
    )

    full_path = os.path.join(bss_module_path, bss_module_name)
    bss_module = importlib.import_module(bss_module_name, package=root_package)
    bss_class = getattr(bss_module, bss_class_name)
    connector = bss_class(config = config)
    connector.initialize()
    return connector
