import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Optional, Callable, Union, Iterator

from pydantic import BaseModel

from app_config import AppConfig
from bss.adapters.otp import OTPHandler, SampleOTPHandler
from bss.adapters.session_management import SessionManagement
from bss.sessions import SessionInfo
from bss.types import (UserInfo, EndUser, ContactInfo, CDRInfo,
                       Capabilities,
                       UserCreateResponse,
                       CustomResponse, CustomRequest, UserVoicemailsResponse, UserVoicemailMessagePatch,
                       VoicemailMessageDetails,
                       eval_as_bool)
from module_loader import ModuleLoader
from report_error import raise_webtrit_error


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


class CustomMethodCall(ABC):
    """A prototype for implemeting your own, custom methods in the adapter. 
    
    Do something specific to your app - could be validation of user
    data during signup; or getting a list of 'call-to-action' items
    such as promotions to show in the app; or anything else.        
    """

    def custom_method_public(self,
                             method_name: str,
                             data: CustomRequest,
                             headers: Optional[Dict] = {},
                             tenant_id: str = None,
                             lang: str = None) -> CustomResponse:
        """
        This method is unprotected and is called prior to authenticating the user
        - e.g. while signing up return the list of available packages a customer can pick.
        
        Parameters:
        method_name (str): the first param in the URL of the request (e.g. if your
            app calls /custom/offers/ - then it will be "offers")
        data (CustomRequest AKA Dict): extra info sent in the request body
            (e.g. you send there the data customer already entered such as his/her ZIP code)
        headers (Dict): HTTP headers of the request
        extra_path_params (str): any extra parameters in the URL (e.g. if your app calls
            /custom/offers/98275/ then it will containt "98275"
        tenant_id (str): the tenant ID (if provided) - to separate the processing
            in multi-tentant environment
        
        Returns:
        CustomResponse (Dict): the data to be returned to the app "as is"
        
        """
        pass

    def custom_method_private(self,
                              session: SessionInfo,
                              user_id: str,
                              method_name: str,
                              data: CustomRequest,
                              headers: Optional[Dict] = {},
                              tenant_id: str = None,
                              lang: str = None) -> CustomResponse:
        """Same thing as custom_method_public but is only allowed
        to be called when an app is already established an authenticated
        session on behalf of the user.
        
        The only diff with custom_method_public are extra parameters:

        - session (SessionInfo): full info about the established session 
        - user_id (str):   the user ID (e.g. email address) of the user

        note that we do NOT supply the full user info here to avoid doing
        a query to the external system to retrieve it. For most cases
        knowing it is an authenticated user "xyz" is enough.
        """
        pass


class AutoProvisionByToken(ABC):
    """Establish a new authenticated session based on a temporary token,
    provided via SMS/email/QR code/etc."""

    def autoprovision_session(self, config_token: str, tenant_id: str = None) -> SessionInfo:
        """Verify the token and if it is valid - return the info about a new session."""
        raise NotImplementedError("Override this method in your sub-class")


class InAppSignup(ABC):
    """Allow users to register from the app, passing the data via the WebTrit and adapter
    to the actual BSS system. If you decide to implement it, please think carefully
    about the security and anit-fraud measures you need to take to prevent abuse."""

    # since most adapters do not need to create&delete users or perform custom actions,
    # we do not make these abstract methos, so the developer
    # does not have to bother overriding them with empty methods
    def signup(self, user_data, tenant_id: str = None) -> UserCreateResponse:
        """Create a new user/customer as a part of the sign-up process"""
        raise NotImplementedError("Override this method in your sub-class")

    def delete_user(self, user: UserInfo):
        """Delete an existing user - this functionality is required by
        Google/Apple marketplace if the app allows to sign up"""
        raise NotImplementedError("Override this method in your sub-class")


class BSSAdapter(SessionManagement, OTPHandler,
                 CustomMethodCall, InAppSignup, AutoProvisionByToken):
    # names of config variables to turn on/off capabilities
    CONFIG_CAPABILITIES_OPTIONS = dict(
        PASSWORD=dict(default=True, option=Capabilities.passwordSignin),
        OTP=dict(default=False, option=Capabilities.otpSignin),
        AUTO_PROVISION=dict(default=False, option=Capabilities.autoProvision),
        SIGNUP=dict(default=False, option=Capabilities.signup),
        CDRS=dict(default=False, option=Capabilities.callHistory),
        RECORDINGS=dict(default=False, option=Capabilities.recordings),
        VOICEMAIL=dict(default=False, option=Capabilities.voicemail),
    )
    # what our adapter can do in general (what is coded)
    # should be overridden in the sub-class
    CAPABILITIES = []

    def calculate_capabilities(self) -> List:
        """Calculate the adapter capabilities based on it's settings and config options"""

        capabilities = self.CAPABILITIES
        for option, data in self.CONFIG_CAPABILITIES_OPTIONS.items():
            capability_id = data['option']
            if capability_id in self.CAPABILITIES:
                # we support it in general - let's see if it is enabled in config
                if (cfg_val := self.config.get_conf_val("Capabilities",
                                                        option, default=None)) \
                        is not None:
                    # a value provided in the config
                    cfg_val = eval_as_bool(cfg_val)
                else:
                    # not defined in the config, use default
                    cfg_val = data.get('default', False)

                if cfg_val:
                    # include it
                    capabilities.append(capability_id)
                else:
                    # disabled - remove it
                    capabilities.remove(capability_id)
        return list(set(capabilities))

    def __init__(self, config: AppConfig):
        self.config = config

    def initialize(self) -> bool:
        """Initialize some session-related data, e.g. open a connection
        to the database. This can be done after the creation of a new
        object."""
        self.capabilities = self.calculate_capabilities()

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
    def get_capabilities(self) -> list:
        """Capabilities of your hosted PBX / BSS / your API adapter"""
        return self.capabilities

    @abstractmethod
    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""
        raise NotImplementedError("Override this method in your sub-class")

    @abstractmethod
    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""
        raise NotImplementedError("Override this method in your sub-class")

    def retrieve_voicemails(self, session: SessionInfo, user: UserInfo) -> UserVoicemailsResponse:
        """Obtain user's voicemails"""
        raise NotImplementedError("Override this method in your sub-class")

    def retrieve_voicemail_message_details(self, session: SessionInfo, user: UserInfo,
                                           message_id: str) -> VoicemailMessageDetails:
        """Obtain user's voicemail message details information"""
        raise NotImplementedError("Override this method in your sub-class")

    def retrieve_voicemail_message_attachment(self, session: SessionInfo, message_id: str, file_format: str) -> Union[
        bytes, Iterator]:
        """Obtain the media file for a user's voicemail message"""
        raise NotImplementedError("Override this method in your sub-class")

    def patch_voicemail_message(self, session: SessionInfo, message_id: str,
                                body: UserVoicemailMessagePatch) -> UserVoicemailMessagePatch:
        """Update attributes for a user's voicemail message"""
        raise NotImplementedError("Override this method in your sub-class")

    def delete_voicemail_message(self, session: SessionInfo, message_id: str) -> None:
        """Delete an existing user's voicemail message"""
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

            raise_webtrit_error(401,
                                error_message="Password validation fails",
                                extra_error_code="incorrect_credentials")

        # something is wrong. your code should raise its own exception
        # with a more descriptive message to simplify the process of fixing the problem
        raise_webtrit_error(401, error_message="User authentication error")

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user_data = self.retrieve_user_info(user)
        if user_data:
            return self.produce_user_object(user_data)

        # no such session
        raise_webtrit_error(404, error_message="User not found")

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
        """Create a new user / customer as a part of the sign-up process"""
        raise NotImplementedError("Override this method in your sub-class")

    def create_new_user(self, user_data, tenant_id: str = None) -> UserCreateResponse:
        """Deprecated version"""
        raise NotImplementedError("This method has been renamed to 'signup', update your code")


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
