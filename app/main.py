from __future__ import annotations

from typing import Optional, Union
import os
import sys
from fastapi import FastAPI, APIRouter, Depends, Response, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# from fastapi.responses import JSONResponse
import logging
from pydantic import conint
from datetime import datetime
from report_error import WebTritErrorException
from app_config import AppConfig
import bss.adapters
from bss.adapters import initialize_bss_adapter
from bss.constants import TENANT_ID_HTTP_HEADER
from bss.types import Capabilities, UserInfo, ExtendedUserInfo, Health
from request_trace import RouteWithLogging

from bss.types import (
    BinaryResponse,
    CallRecordingId,
    CreateSessionInternalServerErrorErrorResponse,
    CreateSessionOtpInternalServerErrorErrorResponse,
    CreateSessionOtpMethodNotAllowedErrorResponse,
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
    UserContactIndexResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserHistoryIndexResponse,
    UserInfoShowResponse,
    VerifySessionOtpInternalServerErrorErrorResponse,
    VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse,

)
VERSION="0.0.8"
API_VERSION_PREFIX = "/api/v1"

my_project_path = os.path.dirname(__file__)
sys.path.append(my_project_path)

config = AppConfig()

# set logging
if config.get_conf_val("Debug", default = "False").upper() == "TRUE":
    log_level = logging.DEBUG
else:
    log_level = logging.INFO
if not os.environ.get('PORT'):
    # we are running locally so it is useful to add timestamps
    # since when running in GCP, logs already have timestamps
    logging.basicConfig(level=log_level, format='[%(asctime)s] %(levelname)s: %(message)s')

# Propagate the root logger configuration to all child loggers
logging.getLogger().setLevel(log_level)
logging.getLogger().handlers = logging.getLogger().handlers
logging.getLogger().propagate = True


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
    x_webtrit_tenant_id: Optional[str] = Header(None, alias='X-WebTrit-Tenant-ID'),
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
            status_code=422, code = CreateSessionUnprocessableEntityErrorResponse.validation_error ,
            error_message="Missing login & password"
        )
    
    user = ExtendedUserInfo(user_id = 'N/A', # do not know it yet
                    client_agent = request.headers.get('User-Agent', 'Unknown'),
                    tenant_id = request.headers.get(TENANT_ID_HTTP_HEADER, None),
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

    return bss.refresh_session(body.refresh_token.__root__)



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
            status_code=500, code=42, error_message="Logout failed"
        )

    return Response(content="", status_code=204)

@router.post(
    '/session/otp-create',
    response_model=SessionOtpCreateResponse,
    responses={
        '404': {'model': CreateSessionOtpNotFoundErrorResponse},
        '405': {'model': CreateSessionOtpMethodNotAllowedErrorResponse},
        '422': {'model': CreateSessionOtpUnprocessableEntityErrorResponse},
        '500': {'model': CreateSessionOtpInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def create_session_otp(
    body: SessionOtpCreateRequest,
    x_webtrit_tenant_id: Optional[str] = Header(None, alias='X-WebTrit-Tenant-ID'),
) -> Union[
    SessionOtpCreateResponse,
    CreateSessionOtpNotFoundErrorResponse,
    CreateSessionOtpMethodNotAllowedErrorResponse,
    CreateSessionOtpUnprocessableEntityErrorResponse,
    CreateSessionOtpInternalServerErrorErrorResponse,
]:
    """
    Generate and send an OTP to the user
    """
    global bss

    if Capabilities.otpSignin not in bss.get_capabilities():
        raise WebTritErrorException(
            status_code=405, code=42, error_message="Method not supported"
        )
    
    if hasattr(body, 'user_ref'):
        user_ref = body.user_ref.__root__
    else:
        raise WebTritErrorException(
            status_code=422,
            code=CreateSessionOtpUnprocessableEntityErrorResponse.validation_error,
            error_message="Cannot find user_ref in the request"
        )

    otp_request = bss.generate_otp(UserInfo(user_id=user_ref))
    return otp_request


@router.post(
    '/session/otp-verify',
    response_model=SessionResponse,
    responses={
        '404': {'model': VerifySessionOtpNotFoundErrorResponse},
        '422': {'model': VerifySessionOtpUnprocessableEntityErrorResponse},
        '500': {'model': VerifySessionOtpInternalServerErrorErrorResponse},
    },
    tags=['session'],
)
def verify_session_otp(
    body: SessionOtpVerifyRequest,
) -> Union[
    SessionResponse,
    VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse,
    VerifySessionOtpInternalServerErrorErrorResponse,
]:
    """
    Verify the OTP and sign in the user
    """
    global bss

    if Capabilities.otpSignin not in bss.get_capabilities():
        raise WebTritErrorException(
            status_code=401, code=42, error_message="Method not supported"
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
    global bss
    return GeneralSystemInfoResponse(
        name=bss.name(), version=bss.version(), supported=bss.get_capabilities()
    )


@router.get(
    '/user',
    response_model=UserInfoShowResponse,
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
) -> (
    Union[
        UserInfoShowResponse,
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

    user = bss.retrieve_user(session, UserInfo( user_id = session.user_id.__root__))

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
    body: UserCreateRequest,
    auth_data: HTTPAuthorizationCredentials = Depends(security),
) -> Union[
    UserCreateResponse,
    CreateUserMethodNotAllowedErrorResponse,
    CreateUserUnprocessableEntityErrorResponse,
    CreateUserInternalServerErrorErrorResponse,
]:
    """
    Create a new user
    """
    pass


@router.get(
    '/user/contacts',
    response_model=UserContactIndexResponse,
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
) -> (
    Union[
        UserContactIndexResponse,
        GetUserContactListUnauthorizedErrorResponse,
        GetUserContactListNotFoundErrorResponse,
        GetUserContactListUnprocessableEntityErrorResponse,
        GetUserContactListInternalServerErrorErrorResponse,
    ]
):
    """
    Get corporate directory (contacts of other users in the same PBX)
    """
    global bss

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.extensions in bss.get_capabilities():
        contacts = bss.retrieve_contacts(session,
                        UserInfo( user_id = session.user_id.__root__))
        return UserContactIndexResponse(items = contacts)

    # not supported by hosted PBX / BSS, return empty list
    return UserContactIndexResponse(items = [])


@router.get(
    '/user/history',
    response_model=UserHistoryIndexResponse,
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
) -> Union[
    UserHistoryIndexResponse,
    GetUserHistoryListUnauthorizedErrorResponse,
    GetUserHistoryListNotFoundErrorResponse,
    GetUserHistoryListUnprocessableEntityErrorResponse,
    GetUserHistoryListInternalServerErrorErrorResponse,
]:
    """
    Get user's call history
    """
    global bss

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.callHistory in bss.get_capabilities():
        calls = bss.retrieve_calls(
            session,
            UserInfo( user_id = session.user_id.__root__),
            items_per_page=items_per_page,
            page=page,
            date_from=time_from,
            date_to=time_to,
        )

        return calls

    # not supported by hosted PBX / BSS, return empty list
    return UserHistoryIndexResponse(__root__=[])

@router.get(
    '/user/recordings/{recording_id}',
    response_model=BinaryResponse,
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
    auth_data: HTTPAuthorizationCredentials = Depends(security)
) -> Union[
    BinaryResponse,
    GetUserRecordingUnauthorizedErrorResponse,
    GetUserRecordingNotFoundErrorResponse,
    GetUserRecordingUnprocessableEntityErrorResponse,
    GetUserRecordingInternalServerErrorErrorResponse,
]:
    global bss

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)
    if Capabilities.recordings in bss.get_capabilities():
        return bss.retrieve_call_recording(
            session, CallRecordingId(__root__=recording_id)
        )

    # not supported by hosted PBX / BSS, return None
    return None


@app.exception_handler(WebTritErrorException)
async def handle_webtrit_error(request, exc):
    return exc.response()


app.include_router(router, prefix=API_VERSION_PREFIX)
