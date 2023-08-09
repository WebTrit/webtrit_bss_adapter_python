from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import orjson

# for now these are just "clones" but we may extend them in the future
# plus we do not want to depend on the names of the objects in the schema too much
# so use these in your code instead of the schema objects
from bss.models import (
    # request / response structures
    SessionCreateRequest as SessionCreateRequest,
    SessionResponse as SessionResponse,

    SessionOtpCreateRequest as SessionOtpCreateRequest,
    SessionOtpCreateResponse as SessionOtpCreateResponse,
    SessionOtpVerifyRequest as SessionOtpVerifyRequest,
    SessionOtpVerifyRequest as OTPVerifyRequest,

    SessionUpdateRequest as SessionUpdateRequest,

    UserCreateRequest as UserCreateRequest,
    UserCreateResponse as UserCreateResponse,

    SystemInfoShowResponse as GeneralSystemInfoResponse,
    UserInfoShowResponse as EndUser,
    UserContactIndexResponse as Contacts,

    # data objects
    BinaryResponse as BinaryResponse,

    Contact as ContactInfo,
    UserHistoryIndexResponse as Calls,
    ErrorResponse as ErrorMsg,
    SupportedEnum as Capabilities,

    CDRInfo as CDRInfo,
    Status as UserServiceActiveStatus,
    SipStatus as SIPRegistrationStatus,
    SipServer as SIPServer,
    SipInfo as SIPInfo,
    ConnectStatus as ConnectStatus,
    Direction as Direction,
    Numbers as Numbers,
    Balance as Balance,
    BalanceType as BalanceType,

    DeliveryChannel as OTPDeliveryChannel,
    Pagination as Pagination,
    CallRecordingId as CallRecordingId,

    # error responses & codes
    CreateSessionOtpInternalServerErrorErrorResponse as CreateSessionOtpInternalServerErrorErrorResponse,
    CreateSessionOtpNotFoundErrorResponse as CreateSessionOtpNotFoundErrorResponse,
    CreateSessionOtpUnprocessableEntityErrorResponse as CreateSessionOtpUnprocessableEntityErrorResponse,

    CreateSessionInternalServerErrorErrorResponse as CreateSessionInternalServerErrorErrorResponse,
    CreateSessionUnauthorizedErrorResponse as CreateSessionUnauthorizedErrorResponse,
    CreateSessionUnprocessableEntityErrorResponse as CreateSessionUnprocessableEntityErrorResponse,

    CreateUserInternalServerErrorErrorResponse as CreateUserInternalServerErrorErrorResponse,
    CreateUserMethodNotAllowedErrorResponse as CreateUserMethodNotAllowedErrorResponse,
    CreateUserUnprocessableEntityErrorResponse as CreateUserUnprocessableEntityErrorResponse,
    DeleteSessionInternalServerErrorErrorResponse as DeleteSessionInternalServerErrorErrorResponse,
    DeleteSessionNotFoundErrorResponse as DeleteSessionNotFoundErrorResponse,
    DeleteSessionUnauthorizedErrorResponse as DeleteSessionUnauthorizedErrorResponse,
    GetSystemInfoInternalServerErrorErrorResponse as GetSystemInfoInternalServerErrorErrorResponse,
    GetUserContactListInternalServerErrorErrorResponse as GetUserContactListInternalServerErrorErrorResponse,
    GetUserContactListNotFoundErrorResponse as GetUserContactListNotFoundErrorResponse,
    GetUserContactListUnauthorizedErrorResponse as GetUserContactListUnauthorizedErrorResponse,
    GetUserContactListUnprocessableEntityErrorResponse as GetUserContactListUnprocessableEntityErrorResponse,
    GetUserHistoryListInternalServerErrorErrorResponse as GetUserHistoryListInternalServerErrorErrorResponse,
    GetUserHistoryListNotFoundErrorResponse as GetUserHistoryListNotFoundErrorResponse,
    GetUserHistoryListUnauthorizedErrorResponse as GetUserHistoryListUnauthorizedErrorResponse,
    GetUserHistoryListUnprocessableEntityErrorResponse as GetUserHistoryListUnprocessableEntityErrorResponse,
    GetUserInfoInternalServerErrorErrorResponse as GetUserInfoInternalServerErrorErrorResponse,
    GetUserInfoNotFoundErrorResponse as GetUserInfoNotFoundErrorResponse,
    GetUserInfoUnauthorizedErrorResponse as GetUserInfoUnauthorizedErrorResponse,
    GetUserInfoUnprocessableEntityErrorResponse as GetUserInfoUnprocessableEntityErrorResponse,
    GetUserRecordingInternalServerErrorErrorResponse as GetUserRecordingInternalServerErrorErrorResponse,
    GetUserRecordingNotFoundErrorResponse as GetUserRecordingNotFoundErrorResponse,
    GetUserRecordingUnauthorizedErrorResponse as GetUserRecordingUnauthorizedErrorResponse,
    GetUserRecordingUnprocessableEntityErrorResponse as GetUserRecordingUnprocessableEntityErrorResponse,
    UpdateSessionInternalServerErrorErrorResponse as UpdateSessionInternalServerErrorErrorResponse,
    UpdateSessionNotFoundErrorResponse as UpdateSessionNotFoundErrorResponse,
    UpdateSessionUnprocessableEntityErrorResponse as UpdateSessionUnprocessableEntityErrorResponse,
    VerifySessionOtpInternalServerErrorErrorResponse as VerifySessionOtpInternalServerErrorErrorResponse,
    VerifySessionOtpNotFoundErrorResponse as VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse as VerifySessionOtpUnprocessableEntityErrorResponse,

    Code  as APIAccessErrorCode,
    Code2 as UserAccessErrorCode,
    Code3 as RefreshTokenErrorCode,
    Code5 as OTPNotFoundErrorCode,
    Code8 as OTPUserDataErrorCode,
    Code9 as FailedAuthCode,
    Code11 as SessionNotFoundCode,
    Code13 as OTPValidationErrCode,
    Code16 as SignupExtAPIErrorCode,
    Code19 as OTPExtAPIErrorCode,
    Code21 as AuthorizationFailureCode,
    Code28 as SignupValidationErrorCode,
    Code32 as FailedAuthIncorrectDataCode,
    Code35 as UserNotFoundCode,

    # Code39 as TokenErrorCode,
    # Code40 as TokenErrorCode2,
    # Code41 as ExternalErrorCode,
    # Code43 as RefreshTokenErrorCode,
    # Code49 as OTPIDNotFoundCode,
    # Code50 as OTPValidationErrCode,
    # Code58 as SignupValidationErrorCode,

)

class UserInfo(BaseModel):
    """Data about the user, on whose behalf the operation is requested"""
    # 
    user_id: str = Field(description = "Unique, immutable user ID," +
                         "this is typically uuid or primary key of the user's record"
        )
    # 
    login: Optional[str] = Field(default=None,
                                 description="""Unique, immutable user ID
        utilized by end-user to login, may change or a user can
        utilize diferent logins e.g. phone number and email"""
        )


class ExtendedUserInfo(UserInfo):
    """Data about the user, on whose behalf the operation is requested"""
    tenant_id: Optional[str] = None # unique ID of tenant's environment
    client_agent: Optional[str] = None # which app the user is using


class OTPCreateResponse(SessionOtpCreateResponse):
    tenant_id: Optional[str] = None # unique ID of tenant's environment   


class OTP(BaseModel):
    """One-time password for user authentication"""
    otp_expected_code: str
    attempts: int = Field(default=0,
                        description="How many times the user has tried to enter the code"
        )
    user_id: str
    expires_at: datetime


class SessionInfo(SessionResponse):
    """Info about a session, initiated by WebTrit core on behalf of user"""
    # long_life_refresh: bool = False
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

def safely_extract_scalar_value(obj: object):
    """When dealing with scalar types in auto-generated models, the value is
     stored in __root__ attribute. This function extracts it - or returns the
     actual value for a scalar"""
    if is_scalar(obj):
        return obj
    if hasattr(obj, "__root__"):
        return obj.__root__
    raise ValueError(f"Cannot extract scalar value from {type(obj)} {obj}")
