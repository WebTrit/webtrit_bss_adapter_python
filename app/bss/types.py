from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional, List

# for now these are just "clones" but we may extend them in the future
# plus we do not want to depend on the names of the objects in the schema too much
# so use these in your code instead of the schema objects
from bss.models import UserInfoResponseSchema as EndUser
from bss.models import ContactsResponseSchema as Contacts
from bss.models import ContactInfoSchema as ContactInfo
from bss.models import HistoryResponseSchema as Calls
from bss.models import CallInfoSchema as CallInfo
from bss.models import ErrorSchema as ErrorMsg
from bss.models import SupportedEnum as Capabilities
from bss.models import CDRInfoSchema as CDRInfo
from bss.models import SipStatusSchema as SIPStatus
from bss.models import SessionApprovedResponseSchema

@dataclass
class UserInfo:
    """Data about the user, on whose behalf the operation is requested"""
    user_id: str # unique, immutable ID
    login: Optional[str] = None # utilized by end-user to login, may change or a user can utilize diferent logins e.g. phone number and email

@dataclass
class ExtendedUserInfo(UserInfo):
    """Data about the user, on whose behalf the operation is requested"""
    tenant_id: Optional[str] = None # unique ID of tenant's environment
    client_agent: Optional[str] = None # which app the user is using

@dataclass
class OTP:
    """One-time password for user authentication"""
    otp_expected_code: str
    user_id: str
    expires_at: datetime


class SessionInfo(SessionApprovedResponseSchema):
    """Info about a session, initiated by WebTrit core on behalf of user"""

    def still_active(self, timestamp=datetime.now()) -> bool:
        """Check whether the session has not yet expired"""

        return self.expires_at > timestamp
