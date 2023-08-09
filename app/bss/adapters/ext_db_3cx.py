from bss.adapters import BSSAdapterExternalDB, AttrMap
from bss.types import (
    OTP,
    SessionInfo,
    EndUser,
    Calls,
    ContactInfo,
    Capabilities,
    Numbers,
    SIPInfo,
    SIPRegistrationStatus,
    UserCreateResponse
)
from abc import ABC, abstractmethod
from bss.sessions import SessionStorage
from bss.dbs.firestore import FirestoreKeyValue
from report_error import WebTritErrorException
from app_config import AppConfig
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from sib_api_v3_sdk.models.send_smtp_email_to import SendSmtpEmailTo
import re
from datetime import datetime
from typing import List
import logging

VERSION = "0.0.1"


class SendEmail(ABC):
    def __init__(self, config: AppConfig):
        """Memorize the config object which will have API keys and other info"""
        self.config = config

    @abstractmethod
    def send(self, to: List[str], template_id: str, **kwargs) -> bool:
        """Send an email"""
        return True


class SendInBlueEmailSender(SendEmail):
    """Send email using sendinblue.com API"""

    def __init__(self, config: AppConfig):
        """Memorize the config object which will have API keys and other info"""
        super().__init__(config)
        self.sib_config = sib_api_v3_sdk.Configuration()
        self.sib_config.api_key["api-key"] = config.get_conf_val(
            "SendInBlue", "API_KEY"
        )
        # self.sib_config.api_key_prefix['api-key'] = 'Bearer'
        self.api_client = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(self.sib_config)
        )

    def send(
        self,
        to: List[str],
        template_id: str,
        params: dict = None,
        **kwargs,
    ) -> bool:
        to_list = [SendSmtpEmailTo(email=r, name="3CX PBX user") for r in to]
        email = sib_api_v3_sdk.SendSmtpEmail(
            to=to_list, template_id=int(template_id), params=params, **kwargs
        )
        try:
            # Send a transactional email
            api_response = self.api_client.send_transac_email(email)
            anonymized_recipients = ",".join(
                [r[0:3] + "***" + r[-3:] for r in to]
            )
            sent_id = (
                api_response.message_id if hasattr(api_response, "message_id") else None
            )

            logging.debug(
                f"Sent message to {anonymized_recipients} using template"
                + f" {template_id}; message_id = {sent_id}"
            )

            return True
        except ApiException as e:
            logging.error(
                f"Exception when calling TransactionalEmailsApi->send_transac_email: {e}"
            )

        return False


class BSS3CXAdapter(BSSAdapterExternalDB):
    """Supply to WebTrit core the information about
    extensions in 3CX PBX. Since 3CX offers no native API to retrive
    this, we rely on extracting data from Google Firestore/Datastore DB,
    where they are imported from 3CX CSV files."""

    # mapping of attributes from the 3CX CSV export, as described
    # https://www.3cx.com/docs/bulk-extension-import/
    # to WebTrit EndUser object
    ATTR_MAP = [
        AttrMap(new_key="login", old_key="Number"),
        AttrMap(new_key="password", old_key="SrvcAccessPwd"),
        AttrMap(new_key="firstname", old_key="FirstName"),
        AttrMap(new_key="lastname", old_key="LastName"),
        AttrMap(new_key="email", old_key="EmailAddress",
                converter=lambda x: x if x else None ), # pydantic will not allow '' as email
        AttrMap(new_key="company_name", converter=lambda x: "Test 3CX"),
        AttrMap(new_key="time_zone", converter=lambda x: "UTC"),
    ]
    NUMBERS_ATTR_MAP = [
        AttrMap(new_key="ext", old_key="Number"),
        AttrMap(
            new_key="main",
            old_key="OutboundCallerID",
            converter=lambda x: BSS3CXAdapter.extract_number(x, "Unknown"),
        ),
        AttrMap(
            new_key="additional",
            old_key="DID",
            converter=lambda x: [
                BSS3CXAdapter.extract_number(y, "Unknown") for y in x.split(":")
            ],
        ),
    ]
    SIP_ATTR_MAP = [
        AttrMap(new_key="phone_number", old_key="Number"),
        AttrMap(new_key="auth_username", old_key="AuthID"),
        AttrMap(new_key="password", old_key="AuthPassword"),
    ]

    def __init__(self, config: AppConfig, *args, **kwargs):
        super().__init__(config, *args, **kwargs)
        self.config = config

        self.sip_server = config.get_conf_val(
            "CFG", "3CX", "SIP_Server", default="127.0.0.1"
        )
        self.sip_port = int(config.get_conf_val(
            "CFG", "3CX", "SIP_Server_Port", default=5060
        ))
        logging.debug(f"3CX SIP server is {self.sip_server}:{self.sip_port}")
        def sip_server_func(x):
            return {
                    "host": self.sip_server,
                    "port": self.sip_port,
                    "use_tcp": False 
                }
        # add mappings to SIP_ATTR_MAP so it includes the SIP server address
        BSS3CXAdapter.SIP_ATTR_MAP.append(
            AttrMap(
                new_key="sip_server",
                converter=sip_server_func,
            )
        )
        BSS3CXAdapter.SIP_ATTR_MAP.append(
            AttrMap(
                new_key="registration_server",
                converter=sip_server_func,
            )
        )

        self.user_db = FirestoreKeyValue(collection_name="3CX")
        self.otp_db = FirestoreKeyValue(collection_name="OTP")
        self.sessions = SessionStorage(
            session_db=FirestoreKeyValue(collection_name="Sessions")
        )
        self.mailer = SendInBlueEmailSender(config)

    @classmethod
    def name(cls) -> str:
        """The name of the adapter"""
        return "3CX"

    @classmethod
    def version(cls) -> str:
        """The version"""
        global VERSION
        return VERSION

    # these are regular class methods
    def get_capabilities(self) -> list:
        """Capabilities of your hosted PBX / BSS / your API adapter"""
        return [
            # log in user with username / password
            Capabilities.passwordSignin,
            # log in user using one-time-password generated on the BSS side
            Capabilities.otpSignin,
            # obtain user's call history
            # Capabilities.callHistory,
            # obtain the list of other extensions in the PBX
            Capabilities.extensions,
            # download call recordings - currently not supported
            # SupportedEnum.recordings
        ]

    @classmethod
    def extract_number(cls, x, default=None):
        if x is None:
            return default
        if m := re.search(r"\d+", x):
            return m.group(0)
        return default

    # def sip_server_info(self) -> SIPServer:
    #     """Return the SIP server information."""
    #     return SIPServer(host=self.sip_server, port=5060)

    def verify_password(self, user_data, password: str) -> bool:
        """Verify that the password is correct"""
        passw_in_db = user_data.get("SrvcAccessPwd", None)

        return passw_in_db == password

    def extract_user_id(self, user_data: object) -> str:
        """Extract user_id (unique and unmutable identifier of the user)
        from the data, retrieved from the DB.
        Called from within BSSAdapterExternalDB.authenticate() method
        """
        return user_data.get("Number", None)

    def extract_user_email(self, user_data: object) -> str:
        """Extract user's email to be used for sending one-time-password
        Called from within SampleOTPHandler.generate_otp() method
        """
        return user_data.get("EmailAddress", None)

    def produce_user_object(self, db_data) -> EndUser:
        """Create an EndUser object (as defined by WebTrit) from the
        data stored in the proprietary DB.

        In our case the DB is Google Firestore, and an object is just a dict.
        """

        # step 1: map the attributes from the proprietary DB to
        # the WebTrit EndUser object where we have a direct mapping
        user_data = self.remap_dict(BSS3CXAdapter.ATTR_MAP, db_data)
        # step 2: more complex cases, e.g. the SIP credentials which need to go
        # as SIPInfo object into the "sip" attribute of the EndUser object
        sip_data = self.remap_dict(BSS3CXAdapter.SIP_ATTR_MAP, db_data)
        user_data["sip"] = SIPInfo(**sip_data)
        # other numbers that the user owns
        number_data = self.remap_dict(BSS3CXAdapter.NUMBERS_ATTR_MAP, db_data)
        user_data["numbers"] = Numbers(**number_data)
        logging.debug(f"Re-mapped {db_data} to {user_data}")
        return EndUser(**user_data)

    def produce_contact_object(self, db_data) -> ContactInfo:
        """Create an EndUser object (as defined by WebTrit) from the
        data stored in the proprietary DB.

        In our case the DB is Google Firestore, and an object is just a dict.
        """

        # step 1: map the attributes from the proprietary DB to
        # the WebTrit EndUser object where we have a direct mapping
        user_data = self.remap_dict(BSS3CXAdapter.ATTR_MAP, db_data)
        # fake the SIP registration status as always on, since we do not
        # want to connect to the real 3CX server to check the actual registration
        user_data["sip_status"] = SIPRegistrationStatus.registered

        # numbers that the user owns
        number_data = self.remap_dict(BSS3CXAdapter.NUMBERS_ATTR_MAP, db_data)
        user_data["numbers"] = Numbers(**number_data)
        logging.debug(f"Re-mapped {db_data} to {user_data}")
        return ContactInfo(**user_data)

    # retrieve_user is provided by the superclass

    def retrieve_contacts(
        self, session: SessionInfo, user_id: str
    ) -> List[ContactInfo]:
        """List of other extensions in the PBX"""

        contacts = [
            self.produce_contact_object(self.user_db[ext_id])
            for ext_id in self.user_db.keys()
            if ext_id != user_id
        ]

        return contacts

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
        pass

    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        pass

    def create_new_user(self, user_data, tenant_id: str = None) -> UserCreateResponse:
        """Create a new user as a part of the sign-up process"""
        raise NotImplementedError("Override this method in your sub-class")
    
    def send_otp_email(self, email_address: str, otp: OTP, from_address: str) -> bool:
        """Send an email message with the OTP code to the user.

        Returns: True if the message was sent successfully, False otherwise.
        
        """
        if otp.expires_at:
            time_left = (otp.expires_at - datetime.now()).total_seconds()
            time_left = 0 if time_left < 0 else time_left
            time_left = str(round(time_left / 60)) # convert to minutes
        else:
            time_left = "N/A"
        # pre-configured template on SendInBlue side
        t_id = self.config.get_mandatory_conf_val('Email', 'LoginOTP', 'Template_ID')
        
        return self.mailer.send(to = [ email_address ],
                         template_id = t_id,
                         params = {
                            "CODE": otp.otp_expected_code,
                            "EXPIRES": time_left
                         })
