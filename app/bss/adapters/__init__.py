from dataclasses import dataclass
import importlib
import logging
import sys
import random
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from bss.models import (
    # ContactsResponseSchema,
    # HistoryResponseSchema,
    SessionApprovedResponseSchema,
    # SigninRequestSchema,
    # OtpCreateRequestSchema,
    OtpCreateResponseSchema,
    OtpVerifyRequestSchema,
    OtpSentType,
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

@dataclass
class OTP:
    """One-time password for user authentication"""
    otp_expected_code: str
    user_id: str
    expires_at: datetime

class BSSAdapter(ABC):
    def __init__(self, config: AppConfig):
        self.config = config
        self.sessions = SessionStorage(config)

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

        session = self.sessions.get_session(access_token=access_token)

        if session:
            if not session.still_active():
                # remove it from the DB
                self.sessions.delete_session(
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
        session = self.sessions.get_session(refresh_token=refresh_token)
        if not session:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid refresh token",
            )
        # everything is in order, create a new session
        session = self.sessions.create_session(user_id)
        self.sessions.store_session(session)
        return session

    def close_session(self, access_token: str) -> bool:
        """Close the API session and logout the user."""
        session = self.sessions.get_session(access_token)
        if session:
            return self.sessions.delete_session(access_token)

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




class BSSAdapterExternalDB(BSSAdapter):
    """Supply to WebTrit core the limited information about
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

    def authenticate(self, user_id: str, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        user = self.user_db.get(user_id, None)
        if user:
            if user["password"] == password:
                # everything is in order, create a session
                session = self.sessions.create_session(user_id)
                self.sessions.store_session(session)
                return session

            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid password",
            )

        # something is wrong. your code should return a more descriptive
        # error message to simplify the process of fixing the problem
        raise WebTritErrorException(
            status_code=401,
            code=42,
            error_message="User authentication error",
        )

    def retrieve_user(self, session: SessionInfo, user_id: str) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user = self.user_db.get(user_id, None)
        if user:
            return EndUser(**user)

        # no such session
        raise WebTritErrorException(
            status_code=404, code=42, error_message="User not found"
        )

    def generate_otp(self, user_id: str) -> OtpCreateResponseSchema:
        """Request that the remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""

        # the code that the user should provide to prove that
        # he/she is who he/she claims to be
        code = random.randrange(100000, 999999)
        code_for_tests = self.config.get_conf_val("PERMANENT_OTP_CODE")
        if code_for_tests:
            # while running automated tests, we have to produce the
            # same OTP as configured in the test suite. make sure
            # this env var is NOT set in production!
            code = int(code_for_tests)
        # so we can see it and use during debug
        logging.info(f"OTP code {code}")

        otp_id = str(uuid.uuid1())

        otp = OTP(
            user_id=user_id,
            otp_expected_code="{:06d}".format(code),
            expires_at=datetime.now() + timedelta(minutes=10),
        )
        # memorize it
        self.otp_db[otp_id] = otp

        return OtpCreateResponseSchema(
            # OTP sender's address so the user can find it easier
            otp_sent_from="sample@webtrit.com",
            otp_id=otp_id,
            otp_sent_type=OtpSentType.email,
        )

    def validate_otp(self, otp: OtpVerifyRequestSchema) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""

        otp_id = otp.otp_id.__root__
        original = self.otp_db.get(otp_id, None)
        if not original:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid OTP ID",
            )

        if original.expires_at < datetime.now():
            raise WebTritErrorException(
                status_code=419,
                code=42,
                error_message="OTP has expired",
            )

        if original.otp_expected_code != otp.code:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid OTP",
            )

        # everything is in order, create a session
        session = self.sessions.create_session(original.user_id)
        self.sessions.store_session(session)
        return session



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
    if bss_module_path:
        # allow to include modules from a directory, other than
        # python's default location and the directory where main.py resides
        sys.path.append(bss_module_path)

    try:
        bss_module = importlib.import_module(bss_module_name, package=root_package)
    except ImportError as e:
        logging.error(f"Error importing module '{bss_module_name}': {e}")
        raise

    logging.info(f"Loaded module: {bss_module_name}")
    try:
        bss_class = getattr(bss_module, bss_class_name)
    except AttributeError as e:
        logging.error(
            f"Error finding class '{bss_class_name}' in module '{bss_module_name}': {e}"
        )
        raise

    adapter = bss_class(config=config)
    adapter.initialize()
    logging.info(f"Initialized BSS adapter: {bss_class_name}")
    return adapter

