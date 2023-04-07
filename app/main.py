from __future__ import annotations

from typing import Optional, Union
import os
import sys
from fastapi import FastAPI, APIRouter, Depends, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# from fastapi.responses import JSONResponse
import logging
from pydantic import conint
from datetime import datetime
from report_error import WebTritErrorException
from app_config import AppConfig
import bss.connectors
from bss.connector import initialize_bss_connector, Capabilities
from request_trace import RouteWithLogging

from bss.models import (
    CallRecordingId,
    ErrorSchema,
    OtpCreateRequestSchema,
    OtpCreateResponseSchema,
    SessionApprovedResponseSchema,
    SigninRequestSchema,
    OtpVerifyRequestSchema,
    RefreshRequestSchema,
    SystemInfoResponseSchema,
    ContactsResponseSchema,
    HistoryResponseSchema,
    UserInfoResponseSchema,
    Health
)

API_VERSION_PREFIX = "/api/v1"

my_project_path = os.path.dirname(__file__)
sys.path.append(my_project_path)

config = AppConfig()

# set logging
if config.get_conf_val("Debug", default = "False").upper() == "TRUE":
    log_level = logging.DEBUG
else:
    log_level = logging.INFO
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
    version="v0.1.5",
    #    servers=[{'url': '/api/v1', 'variables': {}}],
)
security = HTTPBearer()
router = APIRouter(route_class=RouteWithLogging)

bss = initialize_bss_connector(bss.connectors.__name__, config)

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
    "/session",
    response_model=SessionApprovedResponseSchema,
    responses={"422": {"model": ErrorSchema}, "500": {"model": ErrorSchema}},
    tags=["session"],
)
def login_operation(
    body: SigninRequestSchema,
) -> Union[SessionApprovedResponseSchema, ErrorSchema]:
    """
    Login user using username and password
    """
    global bss

    session = bss.authenticate(body.login, body.password)

    data = vars(session)
    return SessionApprovedResponseSchema(**data)


@router.put(
    "/session",
    response_model=SessionApprovedResponseSchema,
    responses={"422": {"model": ErrorSchema}, "500": {"model": ErrorSchema}},
    tags=["session"],
)
def refresh_operation(
    body: RefreshRequestSchema,
) -> Union[SessionApprovedResponseSchema, ErrorSchema]:
    """
    Refresh user session
    """
    global bss

    return bss.refresh_session(body.user_id, body.refresh_token.__root__)


@router.delete(
    "/session",
    response_model=None,
    responses={"500": {"model": ErrorSchema}},
    tags=["session"],
)
def logout_operation(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
) -> Union[None, ErrorSchema]:
    """
    User logout
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
    "/session/otp-create",
    response_model=OtpCreateResponseSchema,
    responses={
        "422": {"model": ErrorSchema},
        "500": {"model": ErrorSchema},
        "501": {"model": ErrorSchema},
    },
    tags=["session"],
)
def generate_otp(
    body: OtpCreateRequestSchema,
) -> Union[OtpCreateResponseSchema, ErrorSchema]:
    """
    Generate a one-time-password (OTP) and send it to the user
    """
    global bss

    if Capabilities.otpSignin not in bss.get_capabilities():
        raise WebTritErrorException(
            status_code=405, code=42, error_message="Method not supported"
        )

    otp_request = bss.generate_otp(user_id=body.user_ref.__root__)
    return otp_request


@router.post(
    "/session/otp-verify",
    response_model=SessionApprovedResponseSchema,
    responses={"422": {"model": ErrorSchema}, "500": {"model": ErrorSchema}},
    tags=["session"],
)
def verify_otp(
    otp_data: OtpVerifyRequestSchema,
) -> Union[SessionApprovedResponseSchema, ErrorSchema]:
    """
    Verify the OTP, provided by the user
    """
    global bss

    if Capabilities.otpSignin not in bss.get_capabilities():
        raise WebTritErrorException(
            status_code=401, code=42, error_message="Method not supported"
        )

    otp_response = bss.validate_otp(otp_data)
    return otp_response


@router.get(
    "/system-info",
    response_model=SystemInfoResponseSchema,
    responses={"500": {"model": ErrorSchema}},
    tags=["info"],
)
def info_operation() -> Union[SystemInfoResponseSchema, ErrorSchema]:
    """
    Supply information about the capabilities of the hosted PBX system and/or BSS
    """
    global bss
    return SystemInfoResponseSchema(
        name=bss.name(), version=bss.version(), supported=bss.get_capabilities()
    )


@router.get(
    "/user",
    response_model=UserInfoResponseSchema,
    responses={"422": {"model": ErrorSchema}, "500": {"model": ErrorSchema}},
    tags=["user"],
)
def user_info(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
) -> Union[UserInfoResponseSchema, ErrorSchema]:
    """
    Get user information
    """
    global bss
    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    user = bss.retrieve_user(session, session.user_id.__root__)

    return user


@router.get(
    "/user/contacts",
    response_model=ContactsResponseSchema,
    responses={"422": {"model": ErrorSchema}, "500": {"model": ErrorSchema}},
    tags=["user"],
)
def contacts_operation(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
) -> Union[ContactsResponseSchema, ErrorSchema]:
    """
    Get corporate directory (contacts of other users in the same PBX)
    """
    global bss

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.extensions in bss.get_capabilities():
        contacts = bss.retrieve_contacts(session, session.user_id.__root__)
        return contacts

    # not supported by hosted PBX / BSS, return empty list
    return ContactsResponseSchema(__root__=[])


@router.get(
    "/user/history",
    response_model=HistoryResponseSchema,
    responses={
        "405": {"model": ErrorSchema},
        "422": {"model": ErrorSchema},
        "500": {"model": ErrorSchema},
    },
    tags=["user"],
)
def history_operation(
    auth_data: HTTPAuthorizationCredentials = Depends(security),
    page: Optional[conint(ge=1)] = None,
    items_per_page: Optional[conint(ge=1)] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
) -> Union[HistoryResponseSchema, ErrorSchema]:
    """
    Get user's call history
    """
    global bss

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.callHistory in bss.get_capabilities():
        calls = bss.retrieve_calls(
            session,
            session.user_id.__root__,
            items_per_page=items_per_page,
            page=page,
            date_from=date_from,
            date_to=date_to,
        )

        return calls

    # not supported by hosted PBX / BSS, return empty list
    return HistoryResponseSchema(__root__=[])


@router.get(
    "/user/records/{call_recording_id}",
    response_model=bytes,
    responses={"405": {"model": ErrorSchema}, "500": {"model": ErrorSchema}},
    tags=["user"],
)
def call_recording_operation(
    call_recording_id: str, auth_data: HTTPAuthorizationCredentials = Depends(security)
) -> Union[bytes, ErrorSchema]:
    """
    Download a recorded call
    """
    global bss

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)
    if Capabilities.recordings in bss.get_capabilities():
        return bss.retrieve_call_recording(
            session, CallRecordingId(__root__=call_recording_id)
        )

    # not supported by hosted PBX / BSS, return None
    return None


@app.exception_handler(WebTritErrorException)
async def handle_webtrit_error(request, exc):
    return exc.response()


app.include_router(router, prefix=API_VERSION_PREFIX)
