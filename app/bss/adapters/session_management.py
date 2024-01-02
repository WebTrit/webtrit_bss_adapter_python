import logging
from abc import ABC, abstractmethod
from bss.types import (UserInfo, safely_extract_scalar_value)
from bss.sessions import SessionStorage, SessionInfo
from report_error import raise_webtrit_error

class SessionManagement(ABC):
    """Basic session management on our side."""
    def __init__(self) -> None:
        # this should be overridden in the subclass, otherwise
        # you end up storing sessions only in memory
        self.sessions = SessionStorage()

    def validate_session(self, access_token: str) -> SessionInfo:
        """Validate that the supplied API token is still valid."""

        session = self.sessions.get_session(access_token=access_token)

        if session:
            if not session.still_active():
                # remove it from the DB
                self.sessions.delete_session(
                    access_token=access_token,
                    refresh_token=None # keep the refresh token
                )
                raise_webtrit_error(401,
                                    error_message = f"Access token {access_token} expired",
                                    extra_error_code= "access_token_expired")

            return session

        raise_webtrit_error(401, 
                    error_message = f"Invalid access token {access_token}",
                    extra_error_code= "access_token_invalid")

    def refresh_session(self, refresh_token: str) -> SessionInfo:
        """Extend the API session be exchanging the refresh token for
        a new API access token."""
        session = self.sessions.get_session(refresh_token=refresh_token)
        if not session:
            raise_webtrit_error(401, 
                    error_message = f"Invalid refresh token {refresh_token}",
                    extra_error_code = "refresh_token_invalid")


        if not isinstance(session, SessionInfo):
            # accessing some old objects in the DB which do not store refresh token
            # as a separate full object
            raise_webtrit_error(401, 
                    error_message = f"Outdated refresh token {refresh_token} - was stored in the old format",
                    extra_error_code = "old_format")

        access_token = safely_extract_scalar_value(session.access_token)
        if not session.still_active():
            # remove it from the DB
            self.sessions.delete_session(
                access_token=access_token,
                refresh_token=refresh_token
            )
            raise_webtrit_error(401, 
                    error_message = f"Refresh token {refresh_token} expired",
                    extra_error_code = "refresh_token_expired")

        # everything is in order, create a new session
        new_session = self.sessions.create_session(UserInfo(
                            user_id=safely_extract_scalar_value(session.user_id)))
        self.sessions.store_session(new_session)
        logging.debug(f"Authenticated user {safely_extract_scalar_value(new_session.user_id)}" +
                      " via refresh token " +
                      f"{refresh_token}, session {safely_extract_scalar_value(new_session.access_token)} created")
        # remove the old session and old refresh token
        self.sessions.delete_session(access_token, refresh_token=refresh_token)
        return new_session

    def close_session(self, access_token: str) -> bool:
        """Close the API session and logout the user."""
        session = self.sessions.get_session(access_token)
        if session:
            return self.sessions.delete_session(access_token, session.refresh_token)

        raise_webtrit_error(401, 
                    error_message = f"Error closing the session {access_token}")
