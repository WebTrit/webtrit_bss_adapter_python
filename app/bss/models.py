# generated by fastapi-codegen:
#   filename:  .\webtrit-0.0.4.json
#   timestamp: 2023-03-01T14:17:46+00:00

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, conint

class Health(BaseModel):
    status: Optional[str] = Field(
        None, description="A response from the server.", example="OK"
    )

class BalanceType(Enum):
    unknown = "unknown"
    inapplicable = "inapplicable"
    prepaid = "prepaid"
    postpaid = "postpaid"


class BalanceSchema(BaseModel):
    amount: Optional[float] = Field(
        None, description="User's current balance.", example="23.89"
    )
    balance_type: Optional[BalanceType] = Field(
        None,
        description="Meaning of the balance figure for this user.\ninapplicable means the PBX system does not handle\nbilling and does not have the balance data.\nprepaid means the number reflects the funds that\nuser has available for spending and\npostpaid means the balance reflect the amount of\npreviously accumulated charges (how much the user\nowes - to be used in conjunction with a credit_limit).\n",
        example="prepaid",
    )
    credit_limit: Optional[float] = Field(
        None, description="User's credit limit (if applicable).", example="100"
    )
    currency: Optional[str] = Field(
        "$",
        description="Currency symbol or name in ISO 4217:2015 format (e.g. USD).",
        example="$",
    )


class Direction(Enum):
    incoming = "incoming"
    outgoing = "outgoing"


class Status(Enum):
    accepted = "accepted"
    declined = "declined"
    missed = "missed"
    error = "error"


class CallInfoSchema(BaseModel):
    direction: Optional[Direction] = Field(
        None, description="Call direction.", example="outgoing"
    )
    disconnected_reason: Optional[str] = Field(
        None, description="The call disconnect reason.", example="Caller hangup"
    )
    status: Optional[Status] = Field(
        None, description="Call status.", example="accepted"
    )


class CallRecordingId(BaseModel):
    __root__: str = Field(
        ...,
        description="Unique ID of a call recording.",
        example="4a53-9e84-cd822ea20c80",
        title="CallRecordingId",
    )


class DateTimeSchema(BaseModel):
    __root__: datetime = Field(..., title="DateTimeSchema")


class Code(Enum):
    account_not_found = "account_not_found"
    account_session_issue = "account_session_issue"
    code_incorrect = "code_incorrect"
    disabled = "disabled"
    empty_user_ref = "empty_user_ref"
    external_api_issue = "external_api_issue"
    no_signup_account = "no_signup_account"
    otp_id_not_found = "otp_id_not_found"
    otp_id_verified = "otp_id_verified"
    otp_id_verify_attempts_exceeded = "otp_id_verify_attempts_exceeded"
    parameters_apply_issue = "parameters_apply_issue"
    parameters_validate_issue = "parameters_validate_issue"
    refresh_token_expired = "refresh_token_expired"
    refresh_token_incorrect = "refresh_token_incorrect"
    update_custom_field_fail = "update_custom_field_fail"
    update_email_fail = "update_email_fail"


class RefiningItem(BaseModel):
    path: Optional[str] = None
    reason: Optional[str] = None


class ErrorSchema(BaseModel):
    code: Code = Field(..., description="Error code.", example="external_api_issue")
    refining: Optional[List[RefiningItem]] = None


class Pagination(BaseModel):
    items_per_page: Optional[conint(ge=1)] = Field(
        None, description="Number of items per page.", example=100
    )
    items_total: Optional[conint(ge=1)] = Field(
        None, description="Total number of call records.", example=1000
    )
    page: Optional[conint(ge=1)] = Field(
        None, description="Current page number.", example=1
    )


class NumbersSchema(BaseModel):
    additional: Optional[List[str]] = Field(
        None,
        description="List of other phone numbers, associated with the user. This may\ninclude extra phone numbers that the user purchased (also called\ndirect-inward-dials or DID) to ring on his/her VoIP phone;\nand other numbers that can be used to identify him/her in the\naddress book of others (e.g. his/her mobile number).\n",
        example='["15588924899", "256845666523"]',
    )
    ext: Optional[str] = Field(
        None,
        description="User's extension number (short dialing code) in the PBX.",
        example="2719",
    )
    main: str = Field(
        ...,
        description="User's primary phone number (strongly suggested\nto use a full number including the country code -\nso called E.164 format, e.g. 12065551234 for a US\nphone number).\n",
        example="12065551234",
    )


class OtpSentType(Enum):
    email = "email"
    sms = "sms"
    call = "call"
    other = "other"


class OtpId(BaseModel):
    __root__: str = Field(
        ...,
        description="Unique identifier of the OTP request on\nthe hosted PBX / BSS side. This is\nNOT the code that the user will enter, it is an ID which will\nallow to match the orignally generated OTP and the one,\nprovided by the user.\n",
        example="83e7a1eb-1aed-4def-9166-26120727f072",
        title="OtpId",
    )


class OtpVerifyRequestSchema(BaseModel):
    code: str = Field(
        ...,
        description="Code (one-time-password) that the end-user receives from\nthe hosted PBX system or BSS via email/SMS and then uses in\napplication to confirm his/her identity and login.\n",
    )
    otp_id: OtpId


class RefreshToken(BaseModel):
    __root__: str = Field(
        ...,
        description="Single use token to refresh the API session and obtain a new access token.",
        example="y_KL8k_MyIw1fezPk8ngsCjHiAw0Xs5SISng4yelH8x7nqXpoB0iVhw1oT4",
        title="RefreshToken",
    )


class ServerSchema(BaseModel):
    force_tcp: Optional[bool] = Field(
        False, description="Use `tcp` connection instead `udp`.", example=True
    )
    host: str = Field(
        ...,
        description="SIP server address (hostname or IP address).",
        example="example.webtrit.com",
    )
    port: Optional[int] = Field(
        5060,
        description="Port on which SIP server listens for incoming requests.",
        example=5060,
    )
    sip_over_tls: Optional[bool] = Field(
        False, description="Use SSL/TLS SIP connection.", example=True
    )


class SigninRequestSchema(BaseModel):
    login: str = Field(
        ..., description="User's `login` on the hosted PBX system / BSS."
    )
    password: str = Field(
        ..., description="User's `password` on the hosted PBX system / BSS."
    )


class SipInfoSchema(BaseModel):
    display_name: Optional[str] = Field(
        None,
        description="Visible identification of the caller to be included in the SIP request,\nit will be shown to the called person as the caller name.\nIf not provided then `display_name` will be populated with the `login`\n",
        example="John Doe",
    )
    login: str = Field(
        ..., description="Username to be used in SIP requests.", example="12065551234"
    )
    password: str = Field(..., description="SIP password.", example="83&inE@")
    registration_server: Optional[ServerSchema] = None
    sip_server: ServerSchema


class Status1(Enum):
    unknown = "unknown"
    registered = "registered"
    notregistered = "notregistered"


class SipStatusSchema(BaseModel):
    display_name: str = Field(
        ..., description="User name for SIP call.", example="Hleb23"
    )
    status: Status1 = Field(
        ...,
        description="Is this user currently online (registered to the SIP server)?",
        example="registered",
    )


class SupportedEnum(Enum):
    signup = "signup"
    otpSignin = "otpSignin"
    passwordSignin = "passwordSignin"
    recordings = "recordings"
    callHistory = "callHistory"
    extensions = "extensions"


class SystemInfoResponseSchema(BaseModel):
    custom: Optional[Dict[str, str]] = Field(
        None,
        description="Additional custom key-value pairs which will be transferred to the client as is.",
    )
    name: str
    supported: List[SupportedEnum] = Field(
        ...,
        description="What functionality the hosted PBX system / BSS support, returned as an array of possible options.\n\n* `signup` - new customer create support;\n\n* `otpSignin` - user authorization using OTP;\n\n* `passwordSignin` - user authorization using login and password;\n\n* `recordings` - access to call recordings;\n\n* `callHistory` - access to call history;\n\n* `extensions` - obtain the list of other users (contacts);\n",
    )
    version: str


class UserId(BaseModel):
    __root__: str = Field(
        ...,
        description="An primary unique identifier of the user on the hosted PBX system\n/ BSS.\nSince will be used to store all the internal infomation and associate\nit with further application logins, external actions (e.g. PUSH notifications)\nand actions executed on the hosted PBX / BSS side - it is recommended to\nuse as `user_ud` some permanent ID (e.g. ID of the database record\nthat contains the user data) instead of attributes such as email or\nphone number, which may be changed later on.\n",
        example="ffg0j99d822ea20c80",
        title="UserId",
    )


class UserInfoResponseSchema(BaseModel):
    balance: Optional[BalanceSchema] = None
    company_name: Optional[str] = Field(
        None,
        description="The name of the company the user belongs to.",
        example="Auzon",
    )
    email: Optional[EmailStr] = Field(
        None, description="User`s email address.", example="john777@gmail.com"
    )
    firstname: Optional[str] = Field(
        None, description="User's firstname.", example="John"
    )
    lastname: Optional[str] = Field(None, description="User`s lastname.", example="Doe")
    numbers: Optional[NumbersSchema] = None
    sip: Optional[SipInfoSchema] = None
    time_zone: Optional[str] = Field(
        None,
        description="The time zone name in which the user prefers to see the time values\n([time zones list](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)).\nIf not provided used core server time zone.\n",
        example="Europe/Kyiv",
    )


class UserRef(BaseModel):
    __root__: str = Field(
        ...,
        description="An identifier of the user on the hosted PBX system / BSS (something\nthat will allow the remote system to find it for authentication). It can\nbe an actual phone number or some other identifier (e.g. email)\nassociated with the record. If the same user record is being referenced\nby alternative references - it is important that the same `user_id` will\nbe used during the further processing.\n",
        example="12065551234",
        title="UserRef",
    )


class CDRInfoSchema(BaseModel):
    call: Optional[CallInfoSchema] = None
    call_recording_id: Optional[CallRecordingId] = None
    call_start_time: datetime = Field(
        ...,
        description="Datetime of the call start in ISO format (YYYY-MM-DD HH24:mm:ss).",
        example="2022-01-30 21:58:03",
    )
    callee: str = Field(
        ...,
        description="The phone number of the called party - recipient of the call (CLD).",
        example="15896688665",
    )
    caller: str = Field(
        ...,
        description="The phone number of the calling party - originator of the call (CLI).",
        example="2719",
    )
    duration: int = Field(
        ..., description="Call duration (in seconds), 0 for failed calls.", example=29
    )


class ContactInfoSchema(BaseModel):
    company_name: Optional[str] = Field(
        None,
        description="The name of the company the user belongs to.",
        example="Auzon",
    )
    email: Optional[EmailStr] = Field(
        None, description="User's email address.", example="hide_boss@hotmail.com"
    )
    firstname: Optional[str] = Field(
        None, description="User's firstname.", example="Hide"
    )
    lastname: Optional[str] = Field(
        None, description="User's lastname.", example="Boss"
    )
    numbers: Optional[NumbersSchema] = None
    sip: Optional[SipStatusSchema] = None


class ContactsResponseSchema(BaseModel):
    __root__: List[ContactInfoSchema] = Field(..., title="ContactsResponseSchema")


class HistoryResponseSchema(BaseModel):
    items: Optional[List[CDRInfoSchema]] = None
    pagination: Optional[Pagination] = None


class OtpCreateRequestSchema(BaseModel):
    signup: Optional[bool] = Field(
        None, description="Need create new account or not. Default value: false."
    )
    user_ref: UserRef


class OtpCreateResponseSchema(BaseModel):
    otp_id: OtpId
    otp_sent_from: Optional[str] = Field(
        None,
        description="Identification of the OTP sender to allow the user to find the correct message\neasier. Depending on the provided `otp_sent_type`, it can be: an email address,\nphone number, or description for other method.\nFor email in case it gets into\nthe spam folder, add this address to white-list for the future.\n",
    )
    otp_sent_type: Optional[OtpSentType] = Field(
        None,
        description="Type of the media used to send an OTP\n(so the user can be properly instructed where to look for the OTP\n",
    )


class RefreshRequestSchema(BaseModel):
    refresh_token: RefreshToken
    user_id: UserId


class SessionApprovedResponseSchema(BaseModel):
    access_token: str = Field(
        ...,
        description="The `access_token` to be used in subsequent API\nrequests on behalf of the `user` (by default it is\nplaced in the bearer auth HTTP header).\n",
    )
    expires_at: datetime = Field(
        ...,
        description='The date and time (in ISO format "YYYY-MM-DD HH24:MI:SS",\nUTC timezone) when the `access_token` expires.\n',
        example="2022-11-29 19:04:30",
    )
    refresh_token: Optional[RefreshToken] = None
    user_id: UserId
