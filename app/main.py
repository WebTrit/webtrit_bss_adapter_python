from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from typing import Optional, Union

from fastapi import FastAPI, APIRouter, Depends, Response, Request, Header, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import conint
from starlette.responses import StreamingResponse
from starlette.status import HTTP_204_NO_CONTENT

import bss.adapters
from app_config import AppConfig
from bss.adapters import initialize_bss_adapter
from bss.constants import TENANT_ID_HTTP_HEADER, ACCEPT_LANGUAGE_HEADER
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
    # signup
    UserCreateRequest,
    UserCreateResponse,

    Calls,
    EndUser,
    VerifySessionOtpInternalServerErrorErrorResponse,
    VerifySessionOtpNotFoundErrorResponse,
    VerifySessionOtpUnprocessableEntityErrorResponse,
    Pagination,
    SessionInfo,

    # custom methods
    CustomRequest,
    CustomResponse,
    PrivateCustomUnauthorizedErrorResponse,

    SessionAutoProvisionRequest,
    SessionAutoProvisionUnauthorizedErrorResponse,
    SessionAutoProvisionUnprocessableEntityErrorResponse,
    SessionAutoProvisionInternalServerErrorErrorResponse,
    SessionAutoProvisionNotImplementedErrorResponse,

    # voicemail
    VoicemailMessageDetails,
    UserVoicemailsResponse,
    UserVoicemailUnauthorizedErrorResponse,
    UserVoicemailMessagePatch,
    UserVoicemailNotFoundErrorResponse,
    UserVoicemailInternalServerErrorResponse,
    UserVoicemailDetailsUnauthorizedErrorResponse,
    UserVoicemailDetailsNotFoundErrorResponse,
    UserVoicemailDetailsInternalServerErrorResponse,
    UserVoicemailMessageAttachmentUnauthorizedErrorResponse,
    UserVoicemailMessageAttachmentNotFoundErrorResponse,
    UserVoicemailMessageAttachmentInternalServerErrorResponse,
    UserVoicemailMessagePatchUnauthorizedErrorResponse,
    UserVoicemailMessagePatchNotFoundErrorResponse,
    UserVoicemailMessageAttachmentUnprocessableEntityErrorResponse,
    UserVoicemailMessagePatchInternalServerErrorResponse,
    UserVoicemailMessageDeleteUnauthorizedErrorResponse,
    UserVoicemailMessageDeleteNotFoundErrorResponse,
    UserVoicemailMessageDeleteInternalServerErrorResponse,
)
from bss.types import Capabilities, ExtendedUserInfo, Health, safely_extract_scalar_value
from report_error import raise_webtrit_error
from request_trace import RouteWithLogging, log_formatter

VERSION = "0.1.0"
API_VERSION_PREFIX = "/api/v1"

my_project_path = os.path.dirname(__file__)
sys.path.append(my_project_path)

config = AppConfig()

# set logging
if config.get_conf_val("Debug", default="False").upper() == "TRUE":
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


def is_method_allowed(method: Capabilities) -> Response:
    """Raise error in case if a non-implemented (or disabled)
    method is called"""
    global bss_capabilities

    if method not in bss_capabilities:
        raise_webtrit_error(501,
                            f"Method {method} is not supported by adapter {bss.name()} {bss.version()}")
    return True


@app.get(
    "/health-check",
    response_model=Health,
)
def health_check() -> Health:
    """
    Confirm the service is running
    """
    return Health(status='OK')


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
    Login user using user_ref and password
    """
    global bss

    is_method_allowed(Capabilities.passwordSignin)

    if not (body.user_ref and body.password):
        # missing parameters
        raise_webtrit_error(422, "Missing user_ref & password")

    user_ref = safely_extract_scalar_value(body.user_ref)
    user = ExtendedUserInfo(user_id='N/A',  # do not know it yet
                            client_agent=request.headers.get('User-Agent', 'Unknown'),
                            tenant_id=bss.default_id_if_none(x_webtrit_tenant_id),
                            login=user_ref)
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
        raise_webtrit_error(500, "User logout failed")

    return Response(status_code=HTTP_204_NO_CONTENT, headers={'content-type': 'application/json'})


@router.post(
    '/session/auto-provision',
    response_model=SessionResponse,
    responses={
        '401': {'model': SessionAutoProvisionUnauthorizedErrorResponse},
        '422': {'model': SessionAutoProvisionUnprocessableEntityErrorResponse},
        '500': {'model': SessionAutoProvisionInternalServerErrorErrorResponse},
        '501': {'model': SessionAutoProvisionNotImplementedErrorResponse},
    },
    tags=['session'],
)
def autoprovision_session(
        body: SessionAutoProvisionRequest,
        x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),

) -> Union[
    SessionResponse,
    SessionAutoProvisionUnauthorizedErrorResponse,
    SessionAutoProvisionUnprocessableEntityErrorResponse,
    SessionAutoProvisionInternalServerErrorErrorResponse,
    SessionAutoProvisionNotImplementedErrorResponse,
]:
    """
    Establish an authenticated session without any direct interaction with the user
    by utilizing a temporary "provisioning token" (sent via email, SMS, QR code)

    Returns:
    SessionResponse (so the result is identical to the regular login)
    """
    global bss

    is_method_allowed(Capabilities.autoProvision)

    return bss.autoprovision_session(config_token=body.config_token,
                                     tenant_id=bss.default_id_if_none(x_webtrit_tenant_id))


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
    Generate and send an OTP to the usercreate_otp
    """
    global bss

    is_method_allowed(Capabilities.otpSignin)

    if hasattr(body, 'user_ref'):
        user_ref = safely_extract_scalar_value(body.user_ref)
    else:
        raise_webtrit_error(500, "Cannot find user_ref in the request")

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
    global bss

    is_method_allowed(Capabilities.otpSignin)

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
        user_id=safely_extract_scalar_value(session.user_id),
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
def signup(
        body: UserCreateRequest,
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

    Parameters:
    body - dictionary with the user's data

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
    global bss

    is_method_allowed(Capabilities.signup)

    # TODO: think about extra authentification measures
    return bss.signup(body, tenant_id=bss.default_id_if_none(x_webtrit_tenant_id))


# temporary version of the method definition - added manually and not
# auto-generated from the API schema; will be updated later
@router.delete(
    '/user',
    response_model=None,
    responses={
        '401': {'model': DeleteSessionUnauthorizedErrorResponse},
        '404': {'model': DeleteSessionNotFoundErrorResponse},
        '500': {'model': DeleteSessionInternalServerErrorErrorResponse},
    },
    tags=['user'],
)
def delete_user(
        auth_data: HTTPAuthorizationCredentials = Depends(security),
        x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
):
    """
    Delete an existing user - this functionality is required if the app allows to sign up
    """
    global bss

    is_method_allowed(Capabilities.signup)

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)
    user = ExtendedUserInfo(
        user_id=safely_extract_scalar_value(session.user_id),
        tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)
    )
    bss.delete_user(user)
    result = bss.close_session(access_token)
    return Response(content="", status_code=204)


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

    # not raising an error here even if not implemented,
    # so the user will just see an empty contact list
    # is_method_allowed(Capabilities.extensions)

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    if Capabilities.extensions in bss_capabilities:
        contacts = bss.retrieve_contacts(session,
                                         ExtendedUserInfo(
                                             user_id=safely_extract_scalar_value(session.user_id),
                                             tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)))
        return Contacts(items=contacts)

    # not supported by hosted PBX / BSS, return empty list
    return Contacts(items=[], )


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
            ExtendedUserInfo(user_id=safely_extract_scalar_value(session.user_id),
                             tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)),
            page=page,
            items_per_page=items_per_page,
            time_from=time_from,
            time_to=time_to,
        )

        return Calls(items=calls,
                     pagination=Pagination(
                         page=page,
                         items_total=total,
                         items_per_page=items_per_page)
                     )

    # not supported by hosted PBX / BSS, return an empty list
    return Calls(items=[],
                 pagination=Pagination(
                     page=1,
                     items_total=0,
                     items_per_page=100
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

    is_method_allowed(Capabilities.recordings)

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)
    recording: bytes = bss.retrieve_call_recording(
        session, CallRecordingId(__root__=recording_id)
    )

    return Response(content=recording)


@router.get(
    '/user/voicemails',
    response_model=UserVoicemailsResponse,
    responses={
        '401': {'model': UserVoicemailUnauthorizedErrorResponse},
        '404': {'model': UserVoicemailNotFoundErrorResponse},
        '500': {'model': UserVoicemailInternalServerErrorResponse},
    },
    tags=['user'],
)
def get_user_voicemails(
        auth_data: HTTPAuthorizationCredentials = Depends(security),
        x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    UserVoicemailsResponse,
    UserVoicemailUnauthorizedErrorResponse,
    UserVoicemailNotFoundErrorResponse,
    UserVoicemailInternalServerErrorResponse,
]:
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    is_method_allowed(Capabilities.voicemail)

    voicemail = bss.retrieve_voicemails(session, ExtendedUserInfo(
        user_id=safely_extract_scalar_value(session.user_id),
        tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)
    ))

    return voicemail


@router.get(
    '/user/voicemails/{message_id}',
    response_model=VoicemailMessageDetails,
    responses={
        '401': {'model': UserVoicemailDetailsUnauthorizedErrorResponse},
        '404': {'model': UserVoicemailDetailsNotFoundErrorResponse},
        '500': {'model': UserVoicemailDetailsInternalServerErrorResponse},
    },
    tags=['user'],
)
def get_user_voicemail_message_details(
        message_id: str,
        auth_data: HTTPAuthorizationCredentials = Depends(security),
        x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    VoicemailMessageDetails,
    UserVoicemailDetailsUnauthorizedErrorResponse,
    UserVoicemailDetailsNotFoundErrorResponse,
    UserVoicemailDetailsInternalServerErrorResponse,
]:
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    is_method_allowed(Capabilities.voicemail)

    return bss.retrieve_voicemail_message_details(
        session,
        ExtendedUserInfo(
            user_id=safely_extract_scalar_value(session.user_id),
            tenant_id=bss.default_id_if_none(x_webtrit_tenant_id)
        ),
        message_id
    )


@router.patch(
    '/user/voicemails/{message_id}',
    response_model=UserVoicemailMessagePatch,
    responses={
        '401': {'model': UserVoicemailMessagePatchUnauthorizedErrorResponse},
        '404': {'model': UserVoicemailMessagePatchNotFoundErrorResponse},
        '500': {'model': UserVoicemailMessagePatchInternalServerErrorResponse},
    },
    tags=['user'],
)
def patch_user_voicemail_message(
        message_id: str,
        body: UserVoicemailMessagePatch,
        auth_data: HTTPAuthorizationCredentials = Depends(security),
        _x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    UserVoicemailMessagePatch,
    UserVoicemailMessagePatchUnauthorizedErrorResponse,
    UserVoicemailMessagePatchNotFoundErrorResponse,
    UserVoicemailMessagePatchInternalServerErrorResponse,
]:
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    is_method_allowed(Capabilities.voicemail)

    return bss.patch_voicemail_message(session, message_id, body)


@router.delete(
    '/user/voicemails/{message_id}',
    response_model=None,
    responses={
        '401': {'model': UserVoicemailMessageDeleteUnauthorizedErrorResponse},
        '404': {'model': UserVoicemailMessageDeleteNotFoundErrorResponse},
        '500': {'model': UserVoicemailMessageDeleteInternalServerErrorResponse},
    },
    tags=['user'],
)
def delete_user_voicemail_message(
        message_id: str,
        auth_data: HTTPAuthorizationCredentials = Depends(security),
        _x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    None,
    UserVoicemailMessageDeleteUnauthorizedErrorResponse,
    UserVoicemailMessageDeleteNotFoundErrorResponse,
    UserVoicemailMessageDeleteInternalServerErrorResponse,
]:
    global bss, bss_capabilities

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)

    is_method_allowed(Capabilities.voicemail)
    bss.delete_voicemail_message(session, message_id)

    return Response(status_code=204)


@router.get(
    '/user/voicemails/{message_id}/attachment',
    response_class=StreamingResponse,
    responses={
        '401': {'model': UserVoicemailMessageAttachmentUnauthorizedErrorResponse},
        '404': {'model': UserVoicemailMessageAttachmentNotFoundErrorResponse},
        '422': {'model': UserVoicemailMessageAttachmentUnprocessableEntityErrorResponse},
        '500': {'model': UserVoicemailMessageAttachmentInternalServerErrorResponse},
    },
    tags=['user'],
)
def get_user_voicemail_message_attachment(
        message_id: str,
        file_format: str = None,
        auth_data: HTTPAuthorizationCredentials = Depends(security),
        _x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
) -> Union[
    BinaryResponse,
    UserVoicemailMessageAttachmentUnauthorizedErrorResponse,
    UserVoicemailMessageAttachmentNotFoundErrorResponse,
    UserVoicemailMessageAttachmentUnprocessableEntityErrorResponse,
    UserVoicemailMessageAttachmentInternalServerErrorResponse,
]:
    global bss, bss_capabilities

    is_method_allowed(Capabilities.voicemail)

    access_token = auth_data.credentials
    session = bss.validate_session(access_token)
    content_iterator = bss.retrieve_voicemail_message_attachment(session, message_id, file_format)

    return StreamingResponse(content_iterator, media_type="application/octet-stream")


@router.post("/custom/public/{method_name}/{extra_path_params:path}",
             response_model=CustomResponse, tags=['custom'])
def custom_method_public(
        request: Request,
        method_name: str,
        body: CustomRequest = Body(default=None),
        x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
        accept_language: Optional[str] = Header(None, alias=ACCEPT_LANGUAGE_HEADER),
        extra_path_params: Optional[str] = None,
) -> CustomResponse:
    """
        The invocation of custom methods not explicitly defined in the documentation,
    expanding functionality through predefined rules.

    """
    global bss

    is_method_allowed(Capabilities.customMethods)

    return bss.custom_method_public(
        method_name,
        data=body,
        headers=dict(request.headers),
        extra_path_params=extra_path_params,
        tenant_id=x_webtrit_tenant_id,
        lang=accept_language,
    )


@router.post(
    "/custom/private/{method_name}/{extra_path_params:path}",
    response_model=CustomResponse,
    responses={'401': {'model': PrivateCustomUnauthorizedErrorResponse}},
    tags=['custom'],
)
def custom_method_private(
        request: Request,
        method_name: str,
        body: CustomRequest = Body(default=None),
        x_webtrit_tenant_id: Optional[str] = Header(None, alias=TENANT_ID_HTTP_HEADER),
        accept_language: Optional[str] = Header(None, alias=ACCEPT_LANGUAGE_HEADER),
        extra_path_params: Optional[str] = None,
        auth_data: HTTPAuthorizationCredentials = Depends(security),
) -> Union[CustomResponse, PrivateCustomUnauthorizedErrorResponse]:
    """
        The invocation of custom methods with access token verification not explicitly
    defined in the documentation, expanding functionality through predefined rules.

    """
    global bss

    is_method_allowed(Capabilities.customMethods)

    access_token = auth_data.credentials
    # ensure user is authenticated
    session = bss.validate_session(access_token)

    return bss.custom_method_private(
        session=session,
        user_id=safely_extract_scalar_value(session.user_id),
        method_name=method_name,
        data=body,
        headers=dict(request.headers),
        extra_path_params=extra_path_params,
        tenant_id=x_webtrit_tenant_id,
        lang=accept_language,
    )


app.include_router(router, prefix=API_VERSION_PREFIX)
