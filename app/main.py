from __future__ import annotations

from typing import Optional, Union, Dict
import os
import sys
from fastapi import FastAPI, APIRouter, Depends, Response, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import logging
from pydantic import conint
from datetime import datetime
from report_error import WebTritErrorException
from app_config import AppConfig
import bss.adapters
from bss.adapters import initialize_bss_adapter
from bss.constants import TENANT_ID_HTTP_HEADER
from bss.types import Capabilities, UserInfo, ExtendedUserInfo, Health, safely_extract_scalar_value
from request_trace import RouteWithLogging, log_formatter

from bss.types import (
    BinaryResponse,
    CallRecordingId,
    CreateSessionInternalServerErrorErrorResponse,
    CreateSessionOtpInternalServerErrorErrorResponse,
    CreateSessionOtpNotFoundErrorResponse,
    CreateSessionOtpUnprocessableEntityErrorResponse,
    CreateSessionUnauthorizedErrorResponse,
    CreateSessionUnprocessableEntityErrorResponse,
    CreateUserInternalServerErrorErrorResponse,
    CreateUserMethodNotAllowedErrorResponse,
    CreateUserUnprocessableEntityErrorResponse,
    DeleteSessionInternalServerErrorErrorResponse,
    DeleteSessionNotFoundErrorResponse,
    DeleteSessionUnauthorizedErrorResponse,
    GeneralSystemInfoResponse,
    GetSystemInfoInternalServerErrorErrorResponse,
    GetUserContactListInternalServerErrorErrorResponse,
    GetUserContactListNotFoundErrorResponse,
    GetUserContactListUnauthorizedErrorResponse,
    GetUserContactListUnprocessableEntityErrorResponse,
    GetUserHistoryListInternalServerErrorErrorResponse,
    GetUserHistoryListNotFoundErrorResponse,
    GetUserHistoryListUnauthorizedErrorResponse,
    GetUserHistoryListUnprocessableEntityErrorResponse,
    GetUserInfoInternalServerErrorErrorResponse,
    GetUserInfoNotFoundErrorResponse,
    GetUserInfoUnauthorizedErrorResponse,
    GetUserInfoUnprocessableEntityErrorResponse,
    GetUserRecordingInternalServerErrorErrorResponse,
    GetUserRecordingNotFoundErrorResponse,
    GetUserRecordingUnauthorizedErrorResponse,
    GetUserRecordingUnprocessableEntityErrorResponse,
    SessionCreateRequest,
    SessionOtpCreateRequest,
    SessionOtpCreateResponse,
    SessionOtpVerifyRequest,
    SessionResponse,
    SessionUpdateRequest,
    UpdateSessionInternalServerErrorErrorResponse,
    UpdateSessionNotFoundErrorResponse,
    UpdateSessionUnprocessableEntityErrorResponse,
    Contacts,
    UserCreateRequest,
    UserCreateResponse,
    Calls,
    EndUser,
    VerifySessionOtpInternalServerErrorErrorResponse,
    VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse,
    Pagination,
    SessionNotFoundCode,
    OTPExtAPIErrorCode,
    OTPValidationErrCode,
    FailedAuthIncorrectDataCode,
    SessionInfo,

    # error responses & codes
    SignupNotAllowedErrorCode

)
VERSION="0.0.9"
API_VERSION_PREFIX = "/api/v1"

my_project_path = os.path.dirname(__file__)
sys.path.append(my_project_path)

config = AppConfig()

# set logging
if config.get_conf_val("Debug", default = "False").upper() == "TRUE":
    log_level = logging.DEBUG
else:
    log_level = logging.INFO

# Create a handler and add the formatter to it
handler = logging.StreamHandler()
handler.setFormatter(log_formatter)

# Add the handler to the logger
logger = logging.getLogger()
logger.addHandler(handler)
# Propagate the root logger configuration to all child loggers
logger.setLevel(log_level)
logger.handlers = logging.getLogger().handlers
logger.propagate = True

app = FastAPI(
    description="""Adapter that translates API requests from WebTrit core
        to a hosted PBX system. It enables to authenticate users,
        obtain their SIP credentials, etc.""",
    title="Sample adapter for connecting WebTrit to a BSS",
    version=VERSION,
    #    servers=[{'url': '/api/v1', 'variables': {}}],
)
security = HTTPBearer()

router = APIRouter(route_class=RouteWithLogging)

bss = initialize_bss_adapter(bss.adapters.__name__, config)
bss_capabilities = bss.get_capabilities()

@app.get(
    "/health-check",
    response_model=Health,
)
def health_check() -> Health:
    """
    Confirm the service is running
    """
    return Health(status = 'OK')


@router.post(
    '/session',
    response_model=SessionResponse,
    responses={
        '401': {'model': CreateSessionUnauthorizedErrorResponse},
        '422': {'model': CreateSessionUnprocessableEntityErrorResponse},
        '500': {'model': CreateSessionInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def create_session(
    body: SessionCreateRequest,
    # to retrieve user agent and tenant id from the request
    request: Request,
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
 ) -> Union[
    SessionResponse,
    CreateSessionUnauthorizedErrorResponse,
    CreateSessionUnprocessableEntityErrorResponse,
    CreateSessionInternalServerErrorErrorResponse,
]:
    """
    Login user using username and password
    """
    global bss
    if not (body.login and body.password):
        # missing parameters
        raise WebTritErrorException(
            status_code=422,
            code = FailedAuthIncorrectDataCode.validation_error,
            error_message="Missing login & password"
        )

    user = ExtendedUserInfo(user_id = 'N/A', # do not know it yet
                    client_agent = request.headers.get('User-Agent', 'Unknown'),
                    tenant_id = bss.default_id_if_none(x_webtrit_tenant_id),
                    login = body.login)
    session = bss.authenticate(user, body.password)
    return session

@router.patch(
    '/session',
    response_model=SessionResponse,
    responses={
        '404': {'model': UpdateSessionNotFoundErrorResponse},
        '422': {'model': UpdateSessionUnprocessableEntityErrorResponse},
        '500': {'model': UpdateSessionInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def update_session(
    body: SessionUpdateRequest,
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    SessionResponse,
    UpdateSessionNotFoundErrorResponse,
    UpdateSessionUnprocessableEntityErrorResponse,
    UpdateSessionInternalServerErrorErrorResponse,
]:
    """
    Refresh user's API session and retrieve new tokens
    """
    global bss

    return bss.refresh_session(safely_extract_scalar_value(body.refresh_token))



@router.delete(
    '/session',
    response_model=None,
    responses={
        '401': {'model': DeleteSessionUnauthorizedErrorResponse},
        '404': {'model': DeleteSessionNotFoundErrorResponse},
        '500': {'model': DeleteSessionInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def delete_session(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> (
    Union[
        None,
        DeleteSessionUnauthorizedErrorResponse,
        DeleteSessionNotFoundErrorResponse,
        DeleteSessionInternalServerErrorErrorResponse,
    ]
):
    """
    Sign out the user
    """
    global bss
    access_token = auth_data.credentials
    result = bss.close_session(access_token)
    if not result:
        # we were unable to delete the session - perhaps wrong
        # or expired access token was provided
        raise WebTritErrorException(
            status_code=500,
            code=OTPExtAPIErrorCode.external_api_issue,
            error_message="Logout failed"
        )

    return Response(content="", status_code=204)

@router.post(
    '/session/otp-create',
    response_model=SessionOtpCreateResponse,
    responses={
        '404': {'model': CreateSessionOtpNotFoundErrorResponse},
        '422': {'model': CreateSessionOtpUnprocessableEntityErrorResponse},
        '500': {'model': CreateSessionOtpInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def create_session_otp(
    body: SessionOtpCreateRequest,
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    SessionOtpCreateResponse,
    CreateSessionOtpNotFoundErrorResponse,
    CreateSessionOtpUnprocessableEntityErrorResponse,
    CreateSessionOtpInternalServerErrorErrorResponse,
]:
    """
    Generate and send an OTP to the user
    """
    global bss, bss_capabilities

    if Capabilities.otpSignin not in bss_capabilities:
        raise WebTritErrorException(
            status_code=422,
            error_message="Method not supported",
            code=OTPValidationErrCode.validation_error,
        )

    if hasattr(body, 'user_ref'):
        user_ref = safely_extract_scalar_value(body.user_ref)
    else:
        raise WebTritErrorException(
            status_code=422,
            code=OTPValidationErrCode.validation_error,
            error_message="Cannot find user_ref in the request"
        )

    otp_request = bss.generate_otp(ExtendedUserInfo(
                        user_id=user_ref,
                        tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)))
    return otp_request


@router.post(
    '/session/otp-verify',
    response_model=SessionInfo,
    responses={
        '404': {'model': VerifySessionOtpNotFoundErrorResponse},
        '422': {'model': VerifySessionOtpUnprocessableEntityErrorResponse},
        '500': {'model': VerifySessionOtpInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def verify_session_otp(
    body: SessionOtpVerifyRequest,
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    SessionInfo,
    VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse,
    VerifySessionOtpInternalServerErrorErrorResponse,
]:
    """
    Verify the OTP and sign in the user
    """
    global bss, bss_capabilities

    if Capabilities.otpSignin not in bss_capabilities:
        raise WebTritErrorException(
            status_code=401,
            code=OTPValidationErrCode.validation_error,
            error_message="Method not supported"
        )

    otp_response = bss.validate_otp(body)
    return otp_response


@router.get(
    '/system-info',
    response_model=GeneralSystemInfoResponse,
    responses={'500': {'model': GetSystemInfoInternalServerErrorErrorResponse}},
    tags=['general'],
)
def get_system_info(
    request: Request,
) -> (
    Union[GeneralSystemInfoResponse, GetSystemInfoInternalServerErrorErrorResponse]
):
    """
    Supply information about the capabilities of the hosted PBX system and/or BSS adapter
    """
    global bss, bss_capabilities
    return GeneralSystemInfoResponse(
        name=bss.name(), version=bss.version(), supported=bss_capabilities
    )


@router.get(
    '/user',
    response_model=EndUser,
    responses={
        '401': {'model': GetUserInfoUnauthorizedErrorResponse},
        '404': {'model': GetUserInfoNotFoundErrorResponse},
        '422': {'model': GetUserInfoUnprocessableEntityErrorResponse},
        '500': {'model': GetUserInfoInternalServerErrorErrorResponse},
    },
    tags=['user'],
)
def get_user_info(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> (
    Union[
        EndUser,
        GetUserInfoUnauthorizedErrorResponse,
        GetUserInfoNotFoundErrorResponse,
        GetUserInfoUnprocessableEntityErrorResponse,
        GetUserInfoInternalServerErrorErrorResponse,
    ]
):
    """
    Get user information
    """
    global bss
    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    user = bss.retrieve_user(session, ExtendedUserInfo(
        user_id = safely_extract_scalar_value(session.user_id),
        tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)
        ))

    return user

@router.post(
    '/user',
    response_model=UserCreateResponse,
    responses={
        '405': {'model': CreateUserMethodNotAllowedErrorResponse},
        '422': {'model': CreateUserUnprocessableEntityErrorResponse},
        '500': {'model': CreateUserInternalServerErrorErrorResponse},
    },
    tags=['user'],
)
def create_user(
#   body: UserCreateRequest,
    # cannot figure out how to define this in Pydantic
    body: Dict,
#    auth_data: HTTPAuthorizationCredentials = Depends(security),
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    UserCreateResponse,
    CreateUserMethodNotAllowedErrorResponse,
    CreateUserUnprocessableEntityErrorResponse,
    CreateUserInternalServerErrorErrorResponse,
]:
    """
    Create a new user on the BSS / hosted PBX side as a part of the sign-up process.
    The input data depends on the specifics of your application (e.g. one would sign
    up users just using their mobile phone number, while another would require address,
    email, credit card info, etc.) - so it is not defined by the schema and passed "as is".

    **body** - dictionary with the user's data

    Returns:
        UserCreateResponse, which (upon success) can contain one of the following objects:
            - SessionResponse means that a new user was created and signed in, the object
                contains the access token to be used for subsequent requests
            - SessionOtpCreateResponse means that a new user was created and an OTP
                (email, SMS, etc.) was sent to the user, the object contains the OTP
                request ID. The user should be prompted for the OTP code and then it
                will be validated with OTP request ID.
            - freeform dictionary with the data to be interpreted by the front-end app

    """
    global bss, bss_capabilities

    if Capabilities.signup not in bss_capabilities:
        raise WebTritErrorException(
            status_code=401,
            code=SignupNotAllowedErrorCode.signup_disabled,
            error_message="Method not supported"
        )
    # TODO: think about extra authentification measures
    return bss.signup(body, tenant_id = bss.default_id_if_none(x_webtrit_tenant_id))

@router.get(
    '/user/contacts',
    response_model=Contacts,
    responses={
        '401': {'model': GetUserContactListUnauthorizedErrorResponse},
        '404': {'model': GetUserContactListNotFoundErrorResponse},
        '422': {'model': GetUserContactListUnprocessableEntityErrorResponse},
        '500': {'model': GetUserContactListInternalServerErrorErrorResponse},
    },
    tags=['user'],
)
def get_user_contact_list(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> (
    Union[
        Contacts,
        GetUserContactListUnauthorizedErrorResponse,
        GetUserContactListNotFoundErrorResponse,
        GetUserContactListUnprocessableEntityErrorResponse,
        GetUserContactListInternalServerErrorErrorResponse,
    ]
):
    """
    Get corporate directory (contacts of other users in the same PBX)
    """
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.extensions in bss_capabilities:
        contacts = bss.retrieve_contacts(session,
                        ExtendedUserInfo(
                            user_id = safely_extract_scalar_value(session.user_id),
                            tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)))
        return Contacts(items = contacts)

    # not supported by hosted PBX / BSS, return empty list
    return Contacts(items = [], )


@router.get(
    '/user/history',
    response_model=Calls,
    responses={
        '401': {'model': GetUserHistoryListUnauthorizedErrorResponse},
        '404': {'model': GetUserHistoryListNotFoundErrorResponse},
        '422': {'model': GetUserHistoryListUnprocessableEntityErrorResponse},
        '500': {'model': GetUserHistoryListInternalServerErrorErrorResponse},
    },
    tags=['user'],
)
def get_user_history_list(
    page: Optional[conint(ge=1)] = 1,
    items_per_page: Optional[conint(ge=1)] = 100,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    Calls,
    GetUserHistoryListUnauthorizedErrorResponse,
    GetUserHistoryListNotFoundErrorResponse,
    GetUserHistoryListUnprocessableEntityErrorResponse,
    GetUserHistoryListInternalServerErrorErrorResponse,
]:
    """
    Get user's call history
    """
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.callHistory in bss_capabilities:
        calls, total = bss.retrieve_calls(
            session,
            ExtendedUserInfo(user_id = safely_extract_scalar_value(session.user_id),
                             tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)),
            page = page,
            items_per_page = items_per_page,
            time_from = time_from,
            time_to = time_to,
        )

        return Calls(items = calls,
                     pagination = Pagination(
                         page = page,
                         items_total = total,
                         items_per_page = items_per_page)
                    )

    # not supported by hosted PBX / BSS, return an empty list
    return Calls(items = [],
                 pagination = Pagination(
                     page = 1,
                     items_total = 0,
                     items_per_page = 100
                 ))

@router.get(
    '/user/recordings/{recording_id}',
    # Prevent FastAPI to validate the response as JSON (default response class).
    response_class=Response,
    responses={
        '401': {'model': GetUserRecordingUnauthorizedErrorResponse},
        '404': {'model': GetUserRecordingNotFoundErrorResponse},
        '422': {'model': GetUserRecordingUnprocessableEntityErrorResponse},
        '500': {'model': GetUserRecordingInternalServerErrorErrorResponse},
    },
    tags=['user'],
)
def get_user_recording(
    recording_id: str,
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    BinaryResponse,
    GetUserRecordingUnauthorizedErrorResponse,
    GetUserRecordingNotFoundErrorResponse,
    GetUserRecordingUnprocessableEntityErrorResponse,
    GetUserRecordingInternalServerErrorErrorResponse,
]:
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)
    if Capabilities.recordings in bss_capabilities:
        recording: bytes = bss.retrieve_call_recording(
            session, CallRecordingId(__root__=recording_id)
        )

        return Response(content = recording)

    # not supported by hosted PBX / BSS, return None
    return None

# does not seem to work when using custom route handler
# @app.exception_handler(WebTritErrorException)
# async def handle_webtrit_error(request, exc):
#     return exc.response()

app.include_router(router, prefix=API_VERSION_PREFIX)

