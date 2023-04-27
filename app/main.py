from __future__ import annotations

from typing import Optional, Union
import os
import sys
from fastapi import FastAPI, APIRouter, Depends, Response, Request
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
from bss.types import Capabilities, UserInfo, ExtendedUserInfo, Health, LoginErrCode
from request_trace import RouteWithLogging

from bss.models import (
    BinaryResponse,
    CallRecordingId,
    GeneralSystemInfoResponse,
    InlineResponse401,
    InlineResponse404,
    InlineResponse405,
    InlineResponse422,
    InlineResponse500,
    InlineResponse4041,
    InlineResponse4042,
    InlineResponse4043,
    InlineResponse4221,
    InlineResponse4222,
    InlineResponse4223,
    InlineResponse4224,
    SessionCreateRequest,
    SessionOtpCreateRequest,
    SessionOtpCreateResponse,
    SessionOtpVerifyRequest,
    SessionResponse,
    SessionUpdateRequest,
    UserContactIndexResponse,
    UserHistoryIndexResponse,
    UserInfoShowResponse,

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
        '422': {'model': InlineResponse4221},
        '500': {'model': InlineResponse500},
    },
    tags=['session'],
)
def create_session(
    body: SessionCreateRequest,
    # to retrieve user agent and tenant id from the request
    request: Request
 ) -> Union[SessionResponse, InlineResponse4221, InlineResponse500]:
    """
    Login user using username and password
    """
    global bss
    if not (body.login and body.password):
        # missing parameters
        raise WebTritErrorException(
            status_code=422, code = LoginErrCode.validation_error ,
            error_message="Missing login & password"
        )
    
    user = ExtendedUserInfo(user_id = 'N/A', # do not know it yet
                    client_agent = request.headers.get('User-Agent', 'Unknown'),
                    tenant_id = request.headers.get(TENANT_ID_HTTP_HEADER, None),
                    login = body.login)
    session = bss.authenticate(user, body.password)
    return session


@router.put(
    '/session',
    response_model=SessionResponse,
    responses={
        '404': {'model': InlineResponse404},
        '422': {'model': InlineResponse422},
        '500': {'model': InlineResponse500},
    },
    tags=['session'],
)
def refresh_session(
    body: SessionUpdateRequest,
) -> Union[SessionResponse, InlineResponse404, InlineResponse422, InlineResponse500]:
    """
    Refresh user's API session and retrieve new tokens
    """
    global bss
    user = UserInfo(user_id = body.user_id)
    return bss.refresh_session(user, body.refresh_token.__root__)


@router.delete(
    '/session',
    response_model=None,
    responses={
        '401': {'model': InlineResponse401},
        '404': {'model': InlineResponse404},
        '500': {'model': InlineResponse500},
    },
    tags=['session'],
)
def delete_session(auth_data: HTTPAuthorizationCredentials = Depends(security)) -> (
    Union[None, InlineResponse401, InlineResponse404, InlineResponse500]
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
        '404': {'model': InlineResponse4041},
        '405': {'model': InlineResponse405},
        '422': {'model': InlineResponse4222},
        '500': {'model': InlineResponse500},
    },
    tags=['session'],
)
def otp_create_session(
    body: SessionOtpCreateRequest,
) -> Union[
    SessionOtpCreateResponse,
    InlineResponse4041,
    InlineResponse405,
    InlineResponse4222,
    InlineResponse500,
]:
    """
    Generate and send an OTP to the user
    """
    global bss

    if Capabilities.otpSignin not in bss.get_capabilities():
        raise WebTritErrorException(
            status_code=405, code=42, error_message="Method not supported"
        )
    
    if hasattr(body.__root__, 'user_ref'):
        user_ref = body.__root__.user_ref.__root__
    elif hasattr(body.__root__, 'user_email'):
        user_ref = body.__root__.user_email.__root__
    else:
        raise WebTritErrorException(
            status_code=422, code=42, error_message="Cannot find user ref in the request"
        )

    otp_request = bss.generate_otp(UserInfo(user_id=user_ref))
    return otp_request


@router.post(
    '/session/otp-verify',
    response_model=SessionResponse,
    responses={
        '404': {'model': InlineResponse4042},
        '422': {'model': InlineResponse4223},
        '500': {'model': InlineResponse500},
    },
    tags=['session'],
)
def otp_verify_session(
    body: SessionOtpVerifyRequest,
) -> Union[SessionResponse, InlineResponse4042, InlineResponse4223, InlineResponse500]:
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
    responses={'500': {'model': InlineResponse500}},
    tags=['general'],
)
def show_system_info() -> Union[GeneralSystemInfoResponse, InlineResponse500]:
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
        '401': {'model': InlineResponse401},
        '404': {'model': InlineResponse4043},
        '422': {'model': InlineResponse4224},
        '500': {'model': InlineResponse500},
    },
    tags=['user'],
)
def show_info(auth_data: HTTPAuthorizationCredentials = Depends(security)) -> (
    Union[
        UserInfoShowResponse,
        InlineResponse401,
        InlineResponse4043,
        InlineResponse4224,
        InlineResponse500,
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


@router.get(
    '/user/contacts',
    response_model=UserContactIndexResponse,
    responses={
        '401': {'model': InlineResponse401},
        '404': {'model': InlineResponse4043},
        '422': {'model': InlineResponse4224},
        '500': {'model': InlineResponse500},
    },
    tags=['user'],
)
def index_contact(auth_data: HTTPAuthorizationCredentials = Depends(security)) -> (
    Union[
        UserContactIndexResponse,
        InlineResponse401,
        InlineResponse4043,
        InlineResponse4224,
        InlineResponse500,
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
        return contacts

    # not supported by hosted PBX / BSS, return empty list
    return UserContactIndexResponse(items = [])


@router.get(
    '/user/history',
    response_model=UserHistoryIndexResponse,
    responses={
        '401': {'model': InlineResponse401},
        '404': {'model': InlineResponse4043},
        '422': {'model': InlineResponse4224},
        '500': {'model': InlineResponse500},
    },
    tags=['user'],
)
def index_history(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    page: Optional[conint(ge=1)] = 1,
    items_per_page: Optional[conint(ge=1)] = 100,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
) -> Union[
    UserHistoryIndexResponse,
    InlineResponse401,
    InlineResponse4043,
    InlineResponse4224,
    InlineResponse500,
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
        '401': {'model': InlineResponse401},
        '404': {'model': InlineResponse4043},
        '422': {'model': InlineResponse4224},
        '500': {'model': InlineResponse500},
    },
    tags=['user'],
)
def show_recording(
    recording_id: str,
    auth_data: HTTPAuthorizationCredentials = Depends(security)
) -> Union[
    BinaryResponse,
    InlineResponse401,
    InlineResponse4043,
    InlineResponse4224,
    InlineResponse500,
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
