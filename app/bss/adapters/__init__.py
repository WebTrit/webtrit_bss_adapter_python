from dataclasses import dataclass
import logging
import random
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from bss.types import (UserInfo, EndUser, ContactInfo, CDRInfo, OTP,
                       OTPCreateResponse, OTPVerifyRequest, OTPDeliveryChannel, UserCreateResponse,
                       FailedAuthCode, UserNotFoundCode, SessionNotFoundCode, TokenErrorCode,
                       RefreshTokenErrorCode, TokenErrorCode2, OTPIDNotFoundCode, OTPValidationErrCode,
                       safely_extract_scalar_value)
from bss.sessions import SessionStorage, SessionInfo
from app_config import AppConfig
from report_error import WebTritErrorException
from module_loader import ModuleLoader
from typing import List, Dict, Any, Optional, List

@dataclass
class AttrMap:
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
    old_key: str = None  # if not provided, the old name is used
    converter: callable = None  # custom conversion function


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
                    code=TokenErrorCode.access_token_expired,
                    error_message=f"Access token {access_token} expired",
                )

            return session

        raise WebTritErrorException(
            status_code=401,
            code=TokenErrorCode.access_token_invalid,
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
        if not session.still_active():
            # remove it from the DB
            self.sessions.delete_session(
                access_token=session.access_token,
                refresh_token=refresh_token 
            )
            # raise an error
            raise WebTritErrorException(
                status_code=401,
                code=TokenErrorCode.access_token_expired,
                error_message=f"Refresh token {refresh_token} expired",
            )
        # everything is in order, create a new session
        new_session = self.sessions.create_session(UserInfo(user_id=session.user_id))
        self.sessions.store_session(new_session)
        logging.debug(f"Authenticated user {new_session.user_id} via refresh token {refresh_token}, session {new_session.access_token} created")
        # remove the old session and old refresh token
        self.sessions.delete_session(session.access_token, refresh_token=refresh_token)
        return new_session

    def close_session(self, access_token: str) -> bool:
        """Close the API session and logout the user."""
        session = self.sessions.get_session(access_token)
        if session:
            return self.sessions.delete_session(access_token)

        raise WebTritErrorException(
            status_code=401,
            code=TokenErrorCode2.session_not_found,
            error_message=f"Error closing the session {access_token}",
        )

class OTPHandler(ABC):
    @abstractmethod
    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
        """Request that the remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""
        pass
    @abstractmethod
    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""
        pass

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
    def create_new_user(self, user_data, tenant_id: str = None) -> UserCreateResponse:
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

class SampleOTPHandler(OTPHandler):
    """This is a demo class for handling OTPs, it does not send any
    data to the end-user (only prints it in the log), so it is useful
    for debugging your own application while you are working on establishing
    a way to send real OTPs via SMS or other channel."""

    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
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
            user_id=user.user_id,
            otp_expected_code="{:06d}".format(code),
            expires_at=datetime.now() + timedelta(minutes=15),
        )
        # memorize it
        self.otp_db[otp_id] = otp

        return OTPCreateResponse(
            # OTP sender's address so the user can find it easier
            otp_sent_from="sample@webtrit.com",
            otp_id=otp_id,
            otp_sent_type=OTPDeliveryChannel.email,
        )

    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""

        otp_id = otp.otp_id.__root__
        original = self.otp_db.get(otp_id, None)
        if not original:
            raise WebTritErrorException(
                status_code=401,
                code=OTPIDNotFoundCode.otp_id_not_found,
                error_message="Invalid OTP ID",
            )

        if original.expires_at < datetime.now():
            raise WebTritErrorException(
                status_code=419,
                code=OTPValidationErrCode.otp_id_timeout,
                error_message="OTP has expired",
            )

        if original.otp_expected_code != otp.code:
            raise WebTritErrorException(
                status_code=401,
                code=OTPValidationErrCode.code_incorrect,
                error_message="Invalid OTP",
            )

        # everything is in order, create a session
        session = self.sessions.create_session(UserInfo(user_id = original.user_id))
        self.sessions.store_session(session)
        return session

class BSSAdapterExternalDB(BSSAdapter, SampleOTPHandler):
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

    def find_user_by_login(self, user: UserInfo):
        """The same users may use different login IDs, e.g.
        email, phone number or made-up login username.
        By default we assume login is the same as the user_id,
        but you can override this method in your sub-class to
        enable more creative search by various options. """
        # important: need to use user.login here, not user.user_id
        return self.user_db.get(user.login, None)
    
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
                code=FailedAuthCode.invalid_credentials,
                error_message="Invalid password",
            )

        # something is wrong. your code should return a more descriptive
        # error message to simplify the process of fixing the problem
        raise WebTritErrorException(
            status_code=401,
            code=FailedAuthCode.invalid_credentials,
            error_message="User authentication error",
        )

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

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user_data = self.user_db.get(user.user_id, None)
        if user_data:
            return self.produce_user_object(user_data)

        # no such session
        raise WebTritErrorException(
            status_code=404,
            code=UserNotFoundCode.user_not_found,
            error_message="User not found"
        )

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
    logging.info(f"Initialized BSS adapter: {bss_class_name}")
    return adapter
