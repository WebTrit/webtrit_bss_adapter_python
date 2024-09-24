# generated by fastapi-codegen:
#   filename:  .\webtrit_adapter_v1.1.1.json
#   timestamp: 2023-12-22T14:41:43+00:00

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union, NewType

from pydantic import BaseModel, EmailStr, Field, conint

Code = NewType('Code', str)


class Detail(BaseModel):
    path: Optional[str] = None
    reason: Optional[str] = None


class ErrorResponse(BaseModel):
    code: Optional[Code] = Field(None,
                                 description="""Additional error code identifier to help better handle
                                            situations that fall within the same HTTP error code.
                                            E.g. a request to login is denied with 401 HTTP error
                                            but the code will additionally indicate the specific
                                            reason: username / password are incorrect or the user's
                                            account has been administratively blocked. This code will
                                            be passed to the client, so the app can show a proper message on UI""")
    details: Optional[List[Union[Detail, Dict[str, Any]]]] = Field(
        None,
        description='Additional details related to the error code, which depend on the specific error.\n',
    )
    message: Optional[str] = Field(None, description='Description of the error.')


class GetUserInfoUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class GetUserInfoUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class GetUserInfoNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found`',
    )


class ProvisionSessionAutoUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `incorrect_credentials`',
    )


class UpdateSessionUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`\n- `refresh_token_invalid`\n- `refresh_token_expired`\n- `unknown`',
    )


class GetUserContactListNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found`',
    )


class DeleteUserInfoNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found`',
    )


class SipStatus(Enum):
    registered = 'registered'
    notregistered = 'notregistered'


class CustomRequest(Dict):
    pass


class VerifySessionOtpNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `otp_not_found`',
    )


class GetUserHistoryListUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class Status(Enum):
    active = 'active'
    limited = 'limited'
    blocked = 'blocked'


class RefreshToken(BaseModel):
    __root__: str = Field(
        ...,
        description='A single-use token for refreshing the API session and obtaining a new `access_token`.\n\nWhen the current `access_token` is close to expiration or has already expired, the\n`refresh_token` can be exchanged for a new `access_token`, ensuring uninterrupted access\nto the API without requiring the user to manually sign in again.\n\nPlease note that each `refresh_token` can only be used once, and a new `refresh_token`\nwill be issued along with the new `access_token`.\n',
        title='RefreshToken',
    )


class BinaryResponse(BaseModel):
    __root__: bytes = Field(..., title='BinaryResponse')


class UserId(BaseModel):
    __root__: str = Field(
        ...,
        description='A primary unique identifier of the user on the **Adaptee**.\n\nThis identifier is crucial for the proper functioning of **WebTrit Core**, as it is used\nto store information such as push tokens and other relevant data associated to the user.\n\nThe **Adaptee** must consistently return the same `UserId` for the same user,\nregardless of the `UserRef` used for sign-in.\n',
        example='123456789abcdef0123456789abcdef0',
        title='UserId',
    )


class GetUserContactListUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class CreateSessionOtpUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`\n- `delivery_channel_unspecified`',
    )


class CreateSessionUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `incorrect_credentials`',
    )


class GetUserHistoryListInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class UserRef(BaseModel):
    __root__: str = Field(
        ...,
        description='A reference identifier of the user on the **Adaptee**\n\nThis identifier is entered by the user in client applications and passed\nvia **WebTrit Core** to the **Adaptee** for sign-in purposes.\n\nThe identifier can be a phone number or any other attribute associated\nwith the user. When the same user is accessed using different references,\nit is crucial to ensure that the same `UserId` is assigned to this user.\n',
        example='1234567890',
        title='UserRef',
    )


class DeleteSessionNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`',
    )


class GetSystemInfoInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class VerifySessionOtpUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `otp_already_verified`\n- `otp_verification_attempts_exceeded`\n- `otp_expired`\n- `incorrect_otp_code`',
    )


class SessionOtpCreateRequest(BaseModel):
    user_ref: UserRef


class CustomResponse(Dict):
    pass


class SessionCreateRequest(BaseModel):
    user_ref: Optional[UserRef]
    login: Optional[str] = Field(None, description="User's `login` on the **Adaptee**.")
    password: str = Field(..., description="User's `password` on the **Adaptee**.")


class GetUserRecordingUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class GetUserHistoryListNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found`',
    )


class CreateUserInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class SipServer(BaseModel):
    host: str = Field(
        ...,
        description='The SIP server address, which can be either a hostname or an IP address.',
        example='sip.webtrit.com',
    )
    port: Optional[int] = Field(
        None,
        description='The port on which the SIP server listens for incoming requests.',
        example=5060,
    )


class BalanceType(Enum):
    unknown = 'unknown'
    inapplicable = 'inapplicable'
    prepaid = 'prepaid'
    postpaid = 'postpaid'


class Balance(BaseModel):
    amount: Optional[float] = Field(
        None, description="The user's current balance.", example='50.00'
    )
    balance_type: Optional[BalanceType] = Field(
        None,
        description='Meaning of the balance figure for this user.\n\n* `inapplicable` means the **Adaptee** does not handle\n  billing and does not have the balance data.\n* `prepaid` means the number reflects the funds that\n  the user has available for spending.\n* `postpaid` means the balance reflects the amount of\n  previously accumulated charges (how much the user\n  owes - to be used in conjunction with a `credit_limit`).\n',
    )
    credit_limit: Optional[float] = Field(
        None, description="The user's credit limit (if applicable).", example='100.00'
    )
    currency: Optional[str] = Field(
        '$',
        description='Currency symbol or name in ISO 4217:2015 format (e.g. USD).',
        example='$',
    )


class DeleteUserInfoInternalServerErrorErrorResponse(ErrorResponse):
    pass


class GetUserRecordingNotFoundErrorResponse(ErrorResponse):
    pass


class Pagination(BaseModel):
    items_per_page: Optional[conint(ge=1)] = Field(
        None, description='Number of items presented per page.', example=100
    )
    items_total: Optional[conint(ge=0)] = Field(
        None,
        description='Total number of items found in filtered result set.\nIf no filters are provided, this represents total number\nof items available.\n',
        example=1000,
    )
    page: Optional[conint(ge=1)] = Field(
        None, description='Current page number.', example=1
    )


class ProvisionSessionAutoUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class ProvisionSessionAutoInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class GetUserRecordingUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class CreateSessionOtpInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class SIPTransport(Enum):
    UDP = 'UDP'
    TCP = 'TCP'
    TLS = 'TLS'


class SipInfo(BaseModel):
    auth_username: Optional[str] = Field(
        None,
        description='The username for SIP authorization;\nonly needs to be populated if for a user it differs\nfrom his/her registration ID (which is normally a phone number) supplied in the `username` attribute.\n',
        example='thomas',
    )
    display_name: Optional[str] = Field(
        None,
        description="The visible identification of the caller to be included in the SIP request.\nThis will be shown to the called party as the caller's name. If not provided,\nthe `display_name` will be populated with the `username`.\n",
        example='Thomas A. Anderson',
    )
    password: str = Field(
        ..., description='The password for the SIP account.', example='strong_password'
    )
    transport: Optional[SIPTransport] = Field(..., description='The transport protocol for SIP communication.')
    sip_server: SipServer
    registrar_server: Optional[SipServer] = None
    outbound_proxy_server: Optional[SipServer] = None
    username: str = Field(
        ...,
        description='The identity (typically a phone number but can be some other alphanumeric ID)\nthat should be registered to SIP server to receive incoming calls.\nUsually it is also used as a username for SIP authorization of registrations (SIP REGISTER)\nand outgoing calls (SIP INVITE).\n',
        example='14155551234',
    )


class ProvisionSessionAutoNotImplementedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `functionality_not_implemented`',
    )


class GetUserContactListInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class PrivateCustomUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class CustomForbiddenErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `user_not_allowed`',
    )


class CustomNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `method_not_found`\n- `tenant_not_found`',
    )


class CustomUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class CustomInternalServerErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class DeleteSessionUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class GetUserContactListUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class CreateSessionInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class DeleteSessionInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class UpdateSessionInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class VerifySessionOtpInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class SessionUpdateRequest(BaseModel):
    refresh_token: RefreshToken


class DeliveryChannel(Enum):
    email = 'email'
    sms = 'sms'
    call = 'call'
    other = 'other'


class VerifySessionOtpUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class Direction(Enum):
    incoming = 'incoming'
    outgoing = 'outgoing'


class ConnectStatus(Enum):
    accepted = 'accepted'
    declined = 'declined'
    missed = 'missed'
    error = 'error'


class CreateUserUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`\n- `signup_limit_reached`',
    )


class AccessToken(BaseModel):
    __root__: str = Field(
        ...,
        description="A short-lived token that grants access to the API resources.\n\nIt must be included as an Authorization header in the format `Bearer {access_token}` with each API request.\nThe `access_token` has an expiration date, so it needs to be refreshed periodically using a `refresh_token`\nto maintain uninterrupted access to the API without requiring the user to manually sign in again.\n\nPlease note that the `access_token` should be kept secure and not shared, as it grants access to the user's\ndata and actions within the API.\n",
        title='AccessToken',
    )


class UserCreateRequest(Dict):
    pass


class UpdateSessionNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`',
    )


class GetUserInfoInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class CreateUserMethodNotAllowedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `signup_disabled`',
    )


class OtpId(BaseModel):
    __root__: str = Field(
        ...,
        description='Unique identifier of the OTP request on the **Adapter** and/or **Adaptee** side.\n\nNote: This ID is NOT the code that the user will enter. It serves\nto match the originally generated OTP with the one provided by the user.\n',
        example='12345678-9abc-def0-1234-56789abcdef0',
        title='OtpId',
    )


class CallRecordingId(BaseModel):
    __root__: str = Field(
        ...,
        description='A unique identifier for a call recording, used to reference the recorded media of a specific call.\n',
        title='CallRecordingId',
    )


class CreateSessionUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class GetUserRecordingInternalServerErrorErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class SessionAutoProvisionRequest(BaseModel):
    config_token: str = Field(
        ...,
        description='URL encoded unique token to identify user on the **Adaptee**.',
        example='YKnra0qV3FHeOeMNwotRoP0955gHHHy7y7BWeb',
    )


class SupportedEnum(Enum):
    signup = 'signup'
    otpSignin = 'otpSignin'
    passwordSignin = 'passwordSignin'
    autoProvision = 'autoProvision'
    customMethods = 'customMethods'
    recordings = 'recordings'
    callHistory = 'callHistory'
    extensions = 'extensions'
    voicemail = 'voicemail'
    # adding this manually
    cta_list = 'cta_list'


class SystemInfoShowResponse(BaseModel):
    custom: Optional[Dict[str, str]] = Field(
        None,
        description='Additional custom key-value pairs providing extended information about\nthe **Adaptee** and/or its environment.\n',
    )
    name: str
    supported: List[SupportedEnum] = Field(
        ...,
        description='A list of supported functionalities by the **Adaptee**.\n\nPossible functionalities values:\n* `signup` - supports the creation of new customer accounts\n* `otpSignin` - allows user authorization via One-Time Password (OTP)\n* `passwordSignin` - allows user authorization using login and password\n* `autoProvision` - allows user authorization using config token\n* `recordings` - provides access to call recordings\n* `callHistory` - provides access to call history\n* `extensions` - retrieves the list of other users (contacts)\n',
    )
    version: str


class DeleteUserInfoUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class GetUserHistoryListUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `validation_error`',
    )


class Numbers(BaseModel):
    additional: Optional[List[str]] = Field(
        None,
        description='A list of other phone numbers associated with the user. This may\ninclude extra phone numbers that the user purchased (also called\ndirect-inward-dials or DID) to ring on their VoIP phone,\nand other numbers that can be used to identify them in the\naddress book of others (e.g. their mobile number).\n',
        example=['380441234567', '34911234567'],
    )
    ext: Optional[str] = Field(
        None,
        description="The user's extension number (short dialing code) within the **Adaptee**.\n",
        example='0001',
    )
    main: str = Field(
        ...,
        description="The user's primary phone number. It is strongly suggested\nto use the full number, including the country code\n(also known as the E.164 format).\n",
        example='14155551234',
    )
    sms: Optional[List[str]] = Field(
        None,
        description='A list of phone sms phone numbers associated with the user.\nThese numbers may be associated with third-party SMS services, such as Twilio,\nand can include mobile numbers capable of receiving text messages.',
        example=['380441234567', '+1-212-456-7890'],
    )


class CreateSessionOtpNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `user_not_found`',
    )


class SessionOtpVerifyRequest(BaseModel):
    code: str = Field(
        ...,
        description='Code (one-time-password) that the end-user receives from\nthe **Adaptee** via email/SMS and then uses in\napplication to confirm his/her identity and login.\n',
    )
    otp_id: OtpId


class Contact(BaseModel):
    user_id: Optional[UserId]
    is_current_user: Optional[bool] = Field(
        None,
        description='Indicates whether the contact is associated with the same user who making the request.'
    )
    alias_name: Optional[str] = Field(
        None,
        description="The user's alternative name. May be used for indicate role or position.",
        example='Receptionist',
    )
    company_name: Optional[str] = Field(
        None,
        description='The name of the company the user is associated with.',
        example='Matrix',
    )
    email: Optional[EmailStr] = Field(
        None, description="The user's email address.", example='a.black@matrix.com'
    )
    first_name: Optional[str] = Field(
        None, description="The user's first name.", example='Annabelle'
    )
    last_name: Optional[str] = Field(
        None, description="The user's last name.", example='Black'
    )
    numbers: Numbers
    sip_status: Optional[SipStatus] = Field(
        None,
        description='The current registration status of the user on the SIP server.',
    )


class UserInfoShowResponse(BaseModel):
    alias_name: Optional[str] = Field(
        None,
        description="The user's alternative name. May be used for indicate role or position.",
        example='CTO',
    )
    balance: Optional[Balance] = None
    company_name: Optional[str] = Field(
        None, description='The company the user is associated with.', example='Matrix'
    )
    email: Optional[EmailStr] = Field(
        None, description="The user's email address.", example='neo@matrix.com'
    )
    first_name: Optional[str] = Field(
        None, description="The user's first name.", example='Thomas'
    )
    last_name: Optional[str] = Field(
        None, description="The user's last name.", example='Anderson'
    )
    numbers: Numbers
    sip: SipInfo
    status: Optional[Status] = Field(
        'active',
        description="The user's account status.\n\n* `active`, the user is in an active state and has full access to all functionality\n  (this is the default value and will be assumed if this property is not specified)\n* `limited`, indicates a condition of restricted functionality access\n  (while sign-in and API calls may be allowed, call capabilities could\n  be partially or fully restricted)\n* `blocked`, denotes a state in which the user is blocked, and as a result,\n  client applications won't be able to sign in and will be signed out if\n  previously signed in\n  (API calls might be partially available, but call capabilities are fully\n  restricted)\n\nNote that the number of possible values may be expanded in the future.\n",
    )
    time_zone: Optional[str] = Field(
        None,
        description="The preferred time zone for the user's displayed time values\n(see [time zones list](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)).\nIf not provided, the **WebTrit Core** server time zone is used.\n",
        example='Europe/Kyiv',
    )


class SessionResponse(BaseModel):
    access_token: AccessToken
    refresh_token: Optional[RefreshToken] = None
    user_id: UserId


class UserContactIndexResponse(BaseModel):
    items: Optional[List[Contact]] = None


class SessionOtpCreateResponse(BaseModel):
    delivery_channel: Optional[DeliveryChannel] = Field(
        None,
        description='Specifies the channel used to deliver the OTP to the user\n(e.g., email, SMS, call, or other). This information helps guide the\nuser on where to find the OTP.\n',
    )
    delivery_from: Optional[str] = Field(
        None,
        description='Identifies the sender of the OTP, making it easier for the user to\nlocate the correct message. Depending on the `delivery_channel`, this\nvalue may be an email address, phone number, or a description of an\nalternative method. In the case of email, if the message is marked as\nspam, the user can add this address to a whitelist for future\nreference.\n',
    )
    otp_id: OtpId


class CDRInfo(BaseModel):
    call_id: Optional[str] = Field(
        None,
        description='The field serves as the unique identifier for each call record.',
        example='b2YBUVAUT27eW4QmAd2yBSqG',
    )
    callee: str = Field(
        ...,
        description='The phone number of the called party (recipient of the call, CLD).',
        example='14155551234',
    )
    caller: str = Field(
        ...,
        description='The phone number of the calling party (originator of the call, CLI).',
        example='0001',
    )
    connect_time: Optional[datetime] = Field(
        None,
        description='Datetime of the call connection in ISO format.',
        example='2023-01-01T09:00:00Z',
    )
    direction: Direction = Field(..., description='Indicates the call direction.')
    disconnect_reason: Optional[str] = Field(
        None,
        description='Describes the reason for the call disconnection.',
        example='Caller hangup',
    )
    disconnect_time: Optional[datetime] = Field(
        None,
        description='Datetime of the call disconnection in ISO format.',
        example='2023-01-01T09:01:00Z',
    )
    duration: Optional[int] = Field(
        None, description='Call duration (in seconds), 0 for failed calls.', example=60
    )
    recording_id: Optional[CallRecordingId] = None
    status: ConnectStatus = Field(..., description='Indicates the call status.')


class UserCreateResponse(BaseModel):
    __root__: Union[Dict[str, Any], SessionOtpCreateResponse, SessionResponse] = Field(
        ..., title='UserCreateResponse'
    )


class UserHistoryIndexResponse(BaseModel):
    items: Optional[List[CDRInfo]] = None
    pagination: Optional[Pagination] = None


class VoicemailMessageType(Enum):
    VOICE = 'voice'
    FAX = 'fax'


class VoicemailMessage(BaseModel):
    id: str = Field(
        description='The unique ID of the message.',
        example='1654',
    )
    type: VoicemailMessageType = Field(
        description='The type of the message.'
    )
    duration: Optional[float] = Field(
        description='The duration of the voice message in seconds.',
        example=3.45,
    )
    size: int = Field(
        description='The total size of all attachments in the message in KB.',
        example=5,
    )
    date: datetime = Field(
        description='The delivery date of the message.',
    )
    seen: bool = Field(
        description='Indicates whether this message has been seen.',
        example=False,
    )


class VoicemailMessageAttachment(BaseModel):
    type: str = Field(
        description='The MIME type of the body.',
        example='audio',
    )
    subtype: str = Field(
        description='The MIME subtype of the body.',
        example='basic',
    )
    size: int = Field(
        description='The size of the body in KB.',
        example=5,
    )
    filename: str = Field(
        description='The name of the attached file.',
        example="voice_message_2024-06-07_12-32-03.au",
    )


class VoicemailMessageDetails(VoicemailMessage):
    sender: str = Field(
        description='The sender of the message.',
        example='Caller #123010 <123010@sip.webtrit.com>',
    )
    receiver: str = Field(
        description='The receiver of the message.',
        example='123009 <123009@sip.webtrit.com>',
    )
    attachments: List[VoicemailMessageAttachment]


class UserVoicemailMessagePatch(BaseModel):
    seen: bool


class UserVoicemailsResponse(BaseModel):
    messages: List[VoicemailMessage]
    has_new_messages: bool


class UserVoicemailUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class UserVoicemailNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found`',
    )


class UserVoicemailInternalServerErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class UserVoicemailDetailsUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class UserVoicemailDetailsNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found` \n- `message_not_found`',
    )


class UserVoicemailDetailsInternalServerErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class UserVoicemailMessageAttachmentUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class UserVoicemailMessageAttachmentNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found` \n- `message_not_found`',
    )


class UserVoicemailMessageAttachmentInternalServerErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class UserVoicemailMessageAttachmentUnprocessableEntityErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `unsupported_file_format`',
    )


class UserVoicemailMessagePatchUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class UserVoicemailMessagePatchNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found` \n- `message_not_found`',
    )


class UserVoicemailMessagePatchInternalServerErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )


class UserVoicemailMessageDeleteUnauthorizedErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `authorization_header_missing`\n- `bearer_credentials_missing`\n- `access_token_invalid`\n- `access_token_expired`\n- `unknown`',
    )


class UserVoicemailMessageDeleteNotFoundErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `session_not_found`\n- `user_not_found` \n- `message_not_found`',
    )


class UserVoicemailMessageDeleteInternalServerErrorResponse(ErrorResponse):
    code: Optional[str] = Field(
        None,
        description='`code` field values that are defined (but can be expanded) are:\n- `external_api_issue`',
    )
