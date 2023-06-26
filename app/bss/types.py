from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field
import enum
from datetime import datetime, timedelta
import orjson

# for now these are just "clones" but we may extend them in the future
# plus we do not want to depend on the names of the objects in the schema too much
# so use these in your code instead of the schema objects
from bss.models import (
    BinaryResponse as BinaryResponse,
    UserInfoShowResponse as EndUser,
    UserContactIndexResponse as Contacts,
    Contact as ContactInfo,
    UserHistoryIndexResponse as Calls,
    ErrorResponse as ErrorMsg,
    SupportedEnum as Capabilities,
    UserCreateResponse as UserCreateResponse,
    CDRInfo as CDRInfo,
    SipStatus as SIPStatus,
    SipServer as SIPServer,
    SipInfo as SIPInfo,
    ConnectStatus as ConnectStatus,
    SessionResponse as SessionResponse,
    Numbers as Numbers,

    SessionOtpVerifyRequest as OTPVerifyRequest,
    DeliveryChannel as OTPDeliveryChannel,
    # error codes
    CreateSessionInternalServerErrorErrorResponse1 as CreateSessionInternalServerErrorErrorResponse,
    CreateSessionOtpInternalServerErrorErrorResponse1 as CreateSessionOtpInternalServerErrorErrorResponse,
    CreateSessionOtpMethodNotAllowedErrorResponse1 as CreateSessionOtpMethodNotAllowedErrorResponse,
    CreateSessionOtpNotFoundErrorResponse1 as CreateSessionOtpNotFoundErrorResponse,
    CreateSessionOtpUnprocessableEntityErrorResponse1 as CreateSessionOtpUnprocessableEntityErrorResponse,
    CreateSessionUnauthorizedErrorResponse1 as CreateSessionUnauthorizedErrorResponse,
    CreateSessionUnprocessableEntityErrorResponse1 as CreateSessionUnprocessableEntityErrorResponse,
    CreateUserInternalServerErrorErrorResponse1 as CreateUserInternalServerErrorErrorResponse,
    CreateUserMethodNotAllowedErrorResponse1 as CreateUserMethodNotAllowedErrorResponse,
    CreateUserUnprocessableEntityErrorResponse1 as CreateUserUnprocessableEntityErrorResponse,
    DeleteSessionInternalServerErrorErrorResponse1 as DeleteSessionInternalServerErrorErrorResponse,
    DeleteSessionNotFoundErrorResponse1 as DeleteSessionNotFoundErrorResponse,
    DeleteSessionUnauthorizedErrorResponse1 as DeleteSessionUnauthorizedErrorResponse,
    GetSystemInfoInternalServerErrorErrorResponse1 as GetSystemInfoInternalServerErrorErrorResponse,
    GetUserContactListInternalServerErrorErrorResponse1 as GetUserContactListInternalServerErrorErrorResponse,
    GetUserContactListNotFoundErrorResponse1 as GetUserContactListNotFoundErrorResponse,
    GetUserContactListUnauthorizedErrorResponse1 as GetUserContactListUnauthorizedErrorResponse,
    GetUserContactListUnprocessableEntityErrorResponse1 as GetUserContactListUnprocessableEntityErrorResponse,
    GetUserHistoryListInternalServerErrorErrorResponse1 as GetUserHistoryListInternalServerErrorErrorResponse,
    GetUserHistoryListNotFoundErrorResponse1 as GetUserHistoryListNotFoundErrorResponse,
    GetUserHistoryListUnauthorizedErrorResponse1 as GetUserHistoryListUnauthorizedErrorResponse,
    GetUserHistoryListUnprocessableEntityErrorResponse1 as GetUserHistoryListUnprocessableEntityErrorResponse,
    GetUserInfoInternalServerErrorErrorResponse1 as GetUserInfoInternalServerErrorErrorResponse,
    GetUserInfoNotFoundErrorResponse1 as GetUserInfoNotFoundErrorResponse,
    GetUserInfoUnauthorizedErrorResponse1 as GetUserInfoUnauthorizedErrorResponse,
    GetUserInfoUnprocessableEntityErrorResponse1 as GetUserInfoUnprocessableEntityErrorResponse,
    GetUserRecordingInternalServerErrorErrorResponse1 as GetUserRecordingInternalServerErrorErrorResponse,
    GetUserRecordingNotFoundErrorResponse1 as GetUserRecordingNotFoundErrorResponse,
    GetUserRecordingUnauthorizedErrorResponse1 as GetUserRecordingUnauthorizedErrorResponse,
    GetUserRecordingUnprocessableEntityErrorResponse1 as GetUserRecordingUnprocessableEntityErrorResponse,
    UpdateSessionInternalServerErrorErrorResponse1 as UpdateSessionInternalServerErrorErrorResponse,
    UpdateSessionNotFoundErrorResponse1 as UpdateSessionNotFoundErrorResponse,
    UpdateSessionUnprocessableEntityErrorResponse1 as UpdateSessionUnprocessableEntityErrorResponse,
    VerifySessionOtpInternalServerErrorErrorResponse1 as VerifySessionOtpInternalServerErrorErrorResponse,
    VerifySessionOtpNotFoundErrorResponse1 as VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse1 as VerifySessionOtpUnprocessableEntityErrorResponse,
    UserHistoryIndexResponsePagination as Pagination,
    Code9 as FailedAuthCode,
    Code11 as SessionNotFoundCode,
    Code35 as UserNotFoundCode,
    Code32 as FailedAuthIncorrectDataCode,
    Code39 as TokenErrorCode,
    Code40 as TokenErrorCode2,
    Code41 as ExternalErrorCode,
    Code43 as RefreshTokenErrorCode,
    Code49 as OTPIDNotFoundCode,
    Code50 as OTPValidationErrCode,
    Code58 as SignupValidationErrorCode,
    Code15 as SignupExtAPIErrorCode
)

from bss.models import (
    BinaryResponse,
    CallRecordingId,
    GeneralSystemInfoResponse,
    SessionCreateRequest,
    SessionOtpCreateRequest,
    SessionOtpCreateResponse,
    SessionOtpVerifyRequest,
    SessionResponse,
    SessionUpdateRequest,
    UserContactIndexResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserHistoryIndexResponse,
    UserInfoShowResponse,
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


class OTPCreateResponse(SessionOtpCreateResponse):
    tenant_id: Optional[str] = None # unique ID of tenant's environment   

@dataclass
class OTP:
    """One-time password for user authentication"""
    otp_expected_code: str
    user_id: str
    expires_at: datetime


class SessionInfo(SessionResponse):
    """Info about a session, initiated by WebTrit core on behalf of user"""
    expires_at: Optional[datetime] = None
    tenant_id: Optional[str] = None
    def still_active(self, timestamp=datetime.now()) -> bool:
        """Check whether the session has not yet expired"""

        return self.expires_at > timestamp

class Health(BaseModel):
    status: Optional[str] = Field(
        None, description="A response from the server.", example="OK"
    )





def orjson_dumps(v, *, default):
    return orjson.dumps(v, default=default).decode('utf-8')
 
class Serialiazable(BaseModel):
    """Object that can be converted into JSON structure"""

    class Config:
        json_loads = orjson.loads
        json_dumps = orjson_dumps

    
class SuccessResponse(BaseModel):
    """The success response"""
    message: Optional[str] = None

class SuccessResponseCreate(SuccessResponse):
    """The success response"""
    id: Optional[str] = None

class StatusResponse(BaseModel):
    """The status response"""
    status: Optional[str] = None
    message: Optional[str] = None

class ListResponse(BaseModel):
    """The status response"""
    count: int = 0
    items: List[Any] = []

def is_scalar(obj) -> bool:
    """Return True if the object is a scalar"""
    return isinstance(obj, (str, int, float, bool))

