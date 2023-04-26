from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, List
from pydantic import BaseModel, Field

# for now these are just "clones" but we may extend them in the future
# plus we do not want to depend on the names of the objects in the schema too much
# so use these in your code instead of the schema objects
from bss.models import (
    UserInfoShowResponse as EndUser,
    UserContactIndexResponse as Contacts,
    Contact as ContactInfo,
    UserHistoryIndexResponse as Calls,
    ErrorResponse as ErrorMsg,
    SupportedEnum as Capabilities,
    CDRInfo as CDRInfo,
    SipStatus as SIPStatus,
    SipServer as SIPServer,
    SipInfo as SIPInfo,
    ConnectStatus as ConnectStatus,
    SessionResponse as SessionResponse,
    Numbers as Numbers,
    SessionOtpCreateResponse as OTPCreateResponse,
    SessionOtpVerifyRequest as OTPVerifyRequest,
    DeliveryChannel as OTPDeliveryChannel,
    # error codes
    Code3 as LoginErrCode

)

@dataclass
class UserInfo:
    """Data about the user, on whose behalf the operation is requested"""
    # 
    user_id: str = field(metadata={
        "description": "unique, immutable user ID," +
                         "this is typically uuid or primary key of the user's record"
        })
    # 
    login: Optional[str] = field(default=None,
                                 metadata={
        "description": """Unique, immutable user ID
        utilized by end-user to login, may change or a user can
        utilize diferent logins e.g. phone number and email"""
        })

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


class SessionInfo(SessionResponse):
    """Info about a session, initiated by WebTrit core on behalf of user"""
    expires_at: Optional[datetime] = None 
    def still_active(self, timestamp=datetime.now()) -> bool:
        """Check whether the session has not yet expired"""

        return self.expires_at > timestamp

class Health(BaseModel):
    status: Optional[str] = Field(
        None, description="A response from the server.", example="OK"
    )
