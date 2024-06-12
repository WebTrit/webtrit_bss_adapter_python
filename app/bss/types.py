from enum import Enum
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
from datetime import datetime
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

    # custom methods
    CustomRequest as CustomRequest,
    CustomResponse as CustomResponse,
    PrivateCustomUnauthorizedErrorResponse as PrivateCustomUnauthorizedErrorResponse,

    # signup
    UserCreateRequest as UserCreateRequest,

    # auto-provisioning
    SessionAutoProvisionRequest as SessionAutoProvisionRequest,
    ProvisionSessionAutoUnauthorizedErrorResponse as SessionAutoProvisionUnauthorizedErrorResponse,
    ProvisionSessionAutoUnprocessableEntityErrorResponse as SessionAutoProvisionUnprocessableEntityErrorResponse,
    ProvisionSessionAutoInternalServerErrorErrorResponse as SessionAutoProvisionInternalServerErrorErrorResponse,
    ProvisionSessionAutoNotImplementedErrorResponse as SessionAutoProvisionNotImplementedErrorResponse,

    Code as ErrorCode,

    # voicemail
    UserVoicemailResponse as UserVoicemailResponse,
    VoicemailMessage as VoicemailMessage,
    VoicemailMessageType as VoicemailMessageType,
    UserVoicemailUnauthorizedErrorResponse as UserVoicemailUnauthorizedErrorResponse,
    UserVoicemailNotFoundErrorResponse as UserVoicemailNotFoundErrorResponse,
    UserVoicemailInternalServerErrorResponse as UserVoicemailInternalServerErrorResponse,
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

class CallToActionType(str, Enum):
    BUTTON = 'Button'
    LINK = 'Link'

class CallToAction(BaseModel):
    """An action invitation (button, link, etc.) to be shown in the app, which takes
    the user to the external page - e.g. invite friends, etc."""
    type: CallToActionType = Field(description='How this CTA should be rendered',
                                   example='Link')
    title: Optional[str] = Field(description='The title to be shown to the user',
                                   example='Invite others',
                                   default = None)
    description: Optional[str] = Field(description='Extended info about the action (to be shown in the tool-tip, etc.)',
                                   example='Invite your colleagues or friends to use webTrit, so you can call each other for free',
                                   default = None)
    
class CallToActionLink(CallToAction):
    type: CallToActionType = Field(description='How this CTA should be rendered',
                                   example='Link', default=CallToActionType.LINK)
    url: str = Field(description='URL that the user should be taken to',
                                   example='https://signup.webtrit.com/?email=abc@test.com')

class CallToActionResponse(BaseModel):
    """Set of links to be shown in the app"""
    actions: List[CallToAction] = []

def is_scalar(obj) -> bool:
    """Return True if the object is a scalar"""
    return isinstance(obj, (str, int, float, bool))

def eval_as_bool(val):
    """Interpret value of a config toggle (Y, True, 1, etc.) as boolean."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ['true', 'yes', 'y', '1']
    return False

def safely_extract_scalar_value(obj: object):
    """When dealing with scalar types in auto-generated models, the value is
     stored in __root__ attribute. This function extracts it - or returns the
     actual value for a scalar"""
    if is_scalar(obj):
        return obj
    if hasattr(obj, "__root__"):
        return obj.__root__
    raise ValueError(f"Cannot extract scalar value from {type(obj)} {obj}")

