from fastapi import HTTPException
from fastapi.responses import JSONResponse
import os
import logging

# for now we decided to protect the "initial" API calls
# such as login with username&password or creation
# of OTP by IP address filtering or other methods
# such as SSL certificates
def validate_master_auth_token(token: str) -> bool:
    """Verify the "master" token that protects access to login/otp methods.
    Typically it is configured in the running instance of the application and
    supplied to WebTrit core so it will send requests using it."""

    # TODO: something more elaborate?
    correct_token = os.environ.get("MASTER_TOKEN", "WebTrit")
    if token == correct_token:
        return True

    raise WebTritErrorException(
        status_code=401, code=42, error_message="Invalid master access token"
    )


class WebTritErrorException(HTTPException):
    """Provide error reporting according to WebTrit requirements."""

    def code_to_str(self, code) -> str:
        return str(code).partition(".")[2]

    def __init__(
        self,
        status_code: int,
        error_message: str,
        code: str = None,
        bss_request_trace: dict = None,
        bss_response_trace: dict = None,
    ):
        self.status_code = status_code
        self.error_message = error_message
        self.code = self.code_to_str(code) if code else "code_incorrect"
        self.bss_request_trace = bss_request_trace
        self.bss_response_trace = bss_response_trace
        super().__init__(status_code=status_code, detail=error_message)

    def response(self):
        details = {
            "path": '????',
            "reason": self.error_message,
        }
        traces = {
            name: data
            for name, data in (
                ("request_trace", self.bss_request_trace),
                ("response_trace", self.bss_response_trace),
            )
            if data and len(data) > 0
        }
        if len(traces) > 0:
            details["traces"] = traces
        data = {
            "code": self.code,
            "details": details,
        }
        logging.info(f"Application error {self.error_message} {self.code}" +
            f"traces: {traces} HTTP code: {self.status_code}")
        
        return JSONResponse(content=data, status_code=self.status_code)
