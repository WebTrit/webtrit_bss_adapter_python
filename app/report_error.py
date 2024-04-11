from fastapi import HTTPException
from fastapi.responses import JSONResponse
import os
import logging
import inspect
import traceback

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
    @classmethod
    def record_call_trace(cls, remove_frames: int = 3):
        stack = inspect.stack()
        # only keep useful things in the stack - by default
        # remove the last two frames: this function and __init__ from where it
        # was called
        del stack[0:remove_frames - 1]
        # Extract the relevant information from FrameInfo objects
        formatted_stack = []
        for frame in stack:
            filename = frame.filename
            lineno = frame.lineno
            function = frame.function
            # Get the first line of code context, if available
            line = frame.code_context[0].strip() if frame.code_context else None
            formatted_stack.append((filename, lineno, function, line))

        formatted_stack = traceback.format_list(formatted_stack)
        trace = ''.join(formatted_stack)
        # logging.debug(f"Trace: {trace}")
        return trace

    def code_to_str(self, code) -> str:
        """Convert Enum strings which can be CLASS.abc or just abc into 'abc'"""
        return str(code).split(".")[-1]

    def __init__(
        self,
        status_code: int,
        error_message: str,
        code = None,
        bss_request_trace: dict = None,
        bss_response_trace: dict = None,
        path: str = None,
        called_ordinary: bool = True,
        stack_trace: bool = True,
    ):
        self.status_code = status_code
        self.error_message = error_message
        self.code = self.code_to_str(code) if code else None
        self.call_trace = WebTritErrorException.record_call_trace(
            # remove everything before the call to raise_webtrit_error
            remove_frames = 4 if called_ordinary else 3
        ) if stack_trace else None
        self.bss_request_trace = bss_request_trace
        self.bss_response_trace = bss_response_trace
        self.path = path
        super().__init__(status_code=status_code, detail=error_message)

    def response(self):
        details = {
            "path": self.path,
            # this seems to be the duplication of the 'message'?
            "reason": self.error_message,
            "call_trace": self.call_trace,
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
            "details": details,
            "message": self.error_message,
        }
        if self.code:
            data["code"] = self.code
        logging.info(f"Application error {self.error_message} {self.code}" +
            f"traces: {traces} HTTP code: {self.status_code}")
        
        return JSONResponse(content=data, status_code=self.status_code)


def raise_webtrit_error(
        http_error_code: int,
        error_message: str = "An error has occurred, but the developer has not provided any real details",
        extra_error_code: str = None,
        bss_request_trace: dict = None,
        bss_response_trace: dict = None,):
    raise WebTritErrorException(
        status_code=http_error_code,
        code=extra_error_code,
        error_message=error_message,
        bss_request_trace=bss_request_trace,
        bss_response_trace=bss_response_trace,
        stack_trace=False, # no need to record the stack trace when it is a planned exception
    )
