from bss.adapters import (
    BSSAdapterExternalDB,
    SessionInfo,
    EndUser,
    Contacts,
    Calls,
    ContactInfo,
    Capabilities,
    AttrMap,
)
from bss.models import (
    NumbersSchema,
    OtpCreateResponseSchema,
    OtpVerifyRequestSchema,
    SipInfoSchema,
    ServerSchema,
)

from bss.models import SipStatusSchema as SIPStatus
from bss.sessions import SessionStorage
from bss.dbs.firestore import FirestoreKeyValue
from report_error import WebTritErrorException
from app_config import AppConfig
import re

import logging
from typing import List

VERSION = "0.0.1"


class BSS3CXAdapter(BSSAdapterExternalDB):
    """Supply to WebTrit core the  information about
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
        AttrMap(new_key="email", old_key="EmailAddress"),
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
        AttrMap(new_key="login", old_key="AuthID"),
        AttrMap(new_key="password", old_key="AuthPassword"),
    ]

    def __init__(self, config: AppConfig, *args, **kwargs):
        super().__init__(config, *args, **kwargs)
        self.config = config

        self.sip_server = config.get_conf_val(
            "ExternalDB", "SIP_Server", default="127.0.0.1"
        )
        # add mappings to SIP_ATTR_MAP so it includes the SIP server address
        BSS3CXAdapter.SIP_ATTR_MAP.append(
            AttrMap(
                new_key="sip_server",
                converter=lambda x: {"host": self.sip_server, "port": 5060},
            )
        )
        BSS3CXAdapter.SIP_ATTR_MAP.append(
            AttrMap(
                new_key="registration_server",
                converter=lambda x: {"host": self.sip_server, "port": 5060},
            )
        )

        cred_file = config.get_conf_val("Firestore", "Credentials", default=None)
        self.user_db = FirestoreKeyValue(
            credentials_file=cred_file, collection_name="3CX"
        )

        self.sessions = SessionStorage(
            session_db=FirestoreKeyValue(
                credentials_file=cred_file, collection_name="Sessions"
            )
        )

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
            # Capabilities.otpSignin,
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

    def sip_server_info(self) -> ServerSchema:
        """Return the SIP server information."""
        return ServerSchema(host=self.sip_server, port=5060)

    def verify_password(self, user_data, password: str) -> bool:
        """Verify that the password is correct"""
        passw_in_db = user_data.get("SrvcAccessPwd", None)

        return passw_in_db == password

    def produce_user_object(self, db_data) -> EndUser:
        """Create an EndUser object (as defined by WebTrit) from the
        data stored in the proprietary DB, provided as OurUserInfo"""

        # step 1: map the attributes from the proprietary DB to
        # the WebTrit EndUser object where we have a direct mapping
        user_data = self.remap_dict(BSS3CXAdapter.ATTR_MAP, db_data)
        # step 2: more complex cases, e.g. the SIP credentials which need to go
        # as SipInfoSchema object into the "sip" attribute of the EndUser object
        sip_data = self.remap_dict(BSS3CXAdapter.SIP_ATTR_MAP, db_data)
        user_data["sip"] = SipInfoSchema(**sip_data)
        # numbers that the user owns
        number_data = self.remap_dict(BSS3CXAdapter.NUMBERS_ATTR_MAP, db_data)
        user_data["numbers"] = NumbersSchema(**number_data)
        logging.debug(f"Re-mapped {db_data}\n to {user_data}")
        return EndUser(**user_data)

    def produce_contact_object(self, db_data) -> ContactInfo:
        """Create an EndUser object (as defined by WebTrit) from the
        data stored in the proprietary DB, provided as OurUserInfo"""

        # step 1: map the attributes from the proprietary DB to
        # the WebTrit EndUser object where we have a direct mapping
        user_data = self.remap_dict(BSS3CXAdapter.ATTR_MAP, db_data)
        # step 2: more complex cases, e.g. the SIP credentials which need to go
        # as SipInfoSchema object into the "sip" attribute of the EndUser object
        user_data["sip"] = SIPStatus(
            **{
                "status": "registered",
                "display_name": db_data.get("last_name", "?")
                + ", "
                + db_data.get("first_name", "?"),
            }
        )
        # numbers that the user owns
        number_data = self.remap_dict(BSS3CXAdapter.NUMBERS_ATTR_MAP, db_data)
        user_data["numbers"] = NumbersSchema(**number_data)
        logging.debug(f"Re-mapped {db_data}\n to {user_data}")
        return ContactInfo(**user_data)

    # retrieve_user is provided by the superclass

    def generate_otp(self, user_id: str) -> OtpCreateResponseSchema:
        """Request that a remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""
        pass

    def validate_otp(self, otp: OtpVerifyRequestSchema) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""
        pass

    def retrieve_contacts(self, session: SessionInfo, user_id: str) -> Contacts:
        """List of other extensions in the PBX"""

        contacts = [
            self.produce_contact_object(self.user_db[ext_id])
            for ext_id in self.user_db.keys()
            if ext_id != user_id
        ]

        return Contacts(__root__=contacts)

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
