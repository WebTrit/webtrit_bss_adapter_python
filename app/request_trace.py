import json
import logging
import os
import re
import contextvars
import uuid
from typing import Callable, Optional

from fastapi import HTTPException, Request, Response
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse
import traceback

MAX_LOG_MESSAGE_LENGTH = int(os.getenv("LOG_MAX_MESSAGE_LENGTH", "1000"))

# Add context variable for request ID
current_request_id = contextvars.ContextVar('current_request_id', default="STARTUP")



def truncate_log_message(message: str, max_length: int = MAX_LOG_MESSAGE_LENGTH) -> str:
    """Truncate log message to avoid logging excessively large payloads."""
    if message is None:
        return ""
    if len(message) <= max_length:
        return message
    return f"{message[:max_length]}... [truncated {len(message) - max_length} chars]"


# --- Sensitive-data masking for logs (WT-526) --------------------------------
#
# Debug/trace logging used to emit auth tokens and user passwords verbatim:
# Authorization headers, login request bodies, and backend response bodies
# carrying sip.password / access & refresh tokens. These helpers mask such
# values before they reach the log. Passwords and secrets are fully redacted;
# tokens keep a short head/tail so log lines stay correlatable during debugging.

#: JSON/form keys whose value is a password or secret -> fully redacted.
SECRET_KEYS = {
    "password", "client_secret", "api_password", "secret",
}
#: JSON/form keys whose value is a token/credential -> partially masked.
TOKEN_KEYS = {
    "access_token", "refresh_token", "token", "authorization",
    "api_key", "session_id",
}
_ALL_SENSITIVE_KEYS = SECRET_KEYS | TOKEN_KEYS


def mask_secret(value):
    """Fully redact a password/secret value (reveals nothing, not even length)."""
    if value is None or value == "":
        return value
    return "***"


def mask_token(value):
    """Partially mask a token: keep a short head/tail for correlation, or fully
    redact if it is too short to reveal safely."""
    if value is None or value == "":
        return value
    s = str(value)
    if len(s) <= 13:
        return "***"
    return s[:6] + "***" + s[-4:]


def sanitize_data(obj):
    """Return a copy of ``obj`` with the values of sensitive keys masked.

    Recurses into dicts/lists and never mutates the input, so the caller may
    still send the original structure in a real request after logging it."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SECRET_KEYS:
                result[k] = mask_secret(v)
            elif isinstance(k, str) and k.lower() in TOKEN_KEYS:
                result[k] = mask_token(v)
            else:
                result[k] = sanitize_data(v)
        return result
    if isinstance(obj, (list, tuple)):
        return [sanitize_data(v) for v in obj]
    return obj


_SENSITIVE_TEXT_RE = re.compile(
    r'(?i)("?(?:' + "|".join(sorted(_ALL_SENSITIVE_KEYS, key=len, reverse=True)) +
    r')"?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|[^&\s,}]+)'
)


def _mask_text_fallback(text: str) -> str:
    """Mask sensitive values in a non-JSON string (form-encoded / plain text)."""
    return _SENSITIVE_TEXT_RE.sub(lambda m: f'{m.group(1)}"***"', text)


def sanitize_text(text):
    """Mask sensitive values in a request/response body before logging.

    Accepts a JSON string, a form-encoded string, bytes, or an already-parsed
    dict/list. Never raises: on unparseable input it falls back to regex masking
    and returns the (masked) original text."""
    if text is None:
        return text
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", "replace")
        except Exception:
            return text
    if not isinstance(text, str):
        try:
            return sanitize_data(text)
        except Exception:
            return text
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return json.dumps(sanitize_data(json.loads(text)))
        except (ValueError, TypeError):
            pass
    return _mask_text_fallback(text)


class AddRequestID(logging.Filter):
    """Logging filter that adds request_id to log records"""
    def filter(self, record):
        record.request_id = get_request_id()
        return True

def setup_logging(debug: bool = False):
    """Configure logging with request ID support"""
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # Create log format based on environment
    log_format = ""
    if not os.environ.get("PORT"):
        # Add timestamps when running locally
        log_format += "[%(asctime)s] "
    log_format += "%(levelname)s [Req-ID: %(request_id)s]: %(message)s"

    # Configure handler with formatter and filter
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(log_format))
    handler.addFilter(AddRequestID())

    # Get root logger and configure it
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    for existing_handler in root_logger.handlers[:]:
        root_logger.removeHandler(existing_handler)
    
    root_logger.addHandler(handler)

def set_request_id(request_id: Optional[str]):
    """Set the current request ID in context"""
    if request_id:
        current_request_id.set(request_id)

def get_request_id() -> str:
    """Get the current request ID from context"""
    return current_request_id.get()

def clear_request_id():
    """Clear the current request ID from context"""
    current_request_id.set("STARTUP")

def extract_request_id(request: Request):
    """Extract request ID from request headers"""
    for id in [
        request.headers.get('X-Request-ID', None),
        request.headers.get('X-Cloud-Trace-Context', None),
    ]:
        if id is not None:
            return id
    return 'WT-'+str(uuid.uuid4())

def log_formatted_json(label: str, text):
    """Take JSON (as byte-string) and pretty-print it to the log"""
    if len(text) == 0:
        logging.info(f"{label}: Empty")
        return
    logging.info(f"{label}: {truncate_log_message(text)}")
    return

def log_info(req_body, res_body):
    log_formatted_json("Request body", req_body)
    log_formatted_json("Reply body", res_body)

def log_with_label(label: str, data):
    log_formatted_json(label, data)

debug = True if os.getenv("DEBUG", "False").lower() == "true" else False

# Initialize logging when module is imported
setup_logging(debug)

class RouteWithLogging(APIRoute):
    """Custom route class that logs request and response bodies """
    HEADER_LIST = [ element.strip().lower() for element in
                        os.environ.get("LOG_HEADERS", "X-WebTrit-Tenant-ID").split(",") ]
    LOG_ALL_HEADERS = os.environ.get("LOG_HEADERS_FULL", "False").lower() == "true"
    SENSETIVE_HEADERS = [ 'authorization' ]
    FULLY_LOG_SENSETIVE_HEADERS = os.environ.get("LOG_HEADERS_SENSETIVE", "False").lower() == "true"
    def add_headers_to_log(self, request: Request):
        def obfuscate_string(s: str) -> str:
            """
            Obfuscates the conents of sensetive headers, specifically
            'Authorization' - but leaves a few characters so one can understand
            whether it is a correct one or not. 
            Keeps the first 8 characters and the last 3, replaces the middle
            characters with a single '*'.

            Args:
                s (str): The input string.

            Returns:
                str: The obfuscated string.
            """
            if s is None or len(s) <= 13:  # If the string is too short to obfuscate
                return s
            
            return s[:10] + '***' + s[-3:]

        headers = []
        for header in (request.headers.keys() if self.LOG_ALL_HEADERS else self.HEADER_LIST):
            value = request.headers.get(header)
            if header in self.SENSETIVE_HEADERS and not self.FULLY_LOG_SENSETIVE_HEADERS:
                value = obfuscate_string(value)
            headers.append(f"{header}: '{value}'")
        return "Headers: " + ", ".join(headers)

    def get_ip(self, request: Request):
        client_ip = None
        gcp_ip = request.headers.get("x-forwarded-for")
        if gcp_ip:
            client_ip = gcp_ip.split(",")[0].strip()
        if not client_ip:
            client_ip = request.client.host
        return client_ip

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            # Set request ID from header
            request_id = extract_request_id(request)
            set_request_id(request_id)
            

            req_body = await request.body()
            req_body = sanitize_text(req_body.decode("utf-8").replace("\n", " "))

            if len(req_body) == 0:
                    req_body = "<empty>"
            log_with_label(f"{request.method} request to {request.url.path} " + \
                                self.add_headers_to_log(request) + \
                                f" client IP: {self.get_ip(request)}",
                                f"body: {req_body}"
                            )
            try:
                response = await original_route_handler(request)
            except RequestValidationError as validation_exc:
                # errors when invalid input data is provided
                err_response = JSONResponse(status_code=422,
                                            content=dict(
                                                        error_message = "Input data validation error: " + 
                                                            str(validation_exc.errors()),
                                                        path = request.url.path,
                                                        )
                )

                logging.error(f"Validation exception {validation_exc.errors()}")
                return err_response
            except HTTPException as http_exc:
                if hasattr(http_exc, 'response'):
                    err_response = http_exc.response()
                else:
                    err_response = JSONResponse(
                                        status_code=http_exc.status_code,
                                        content=dict(
                                            message = "Server error: " +
                                                http_exc.detail if hasattr(http_exc, 'detail') else "Unknown error"
                                                )
                    )
                logging.error(f"HTTP exception {http_exc.status_code} {http_exc.detail}")
                err_response.background = BackgroundTask(log_with_label,
                            "Reply", sanitize_text(err_response.body.decode("utf-8").replace("\n", " ")))
                return err_response
            except Exception as e:
                trace_str = traceback.format_exc()
                logging.error(f"Application error: {e} {trace_str.replace(chr(10), ' | ')}")
                return JSONResponse(
                                        status_code=500,
                                        content=dict(
                                            message = f"Server error: {e}",
                                            trace = trace_str
                                        )
                )
            
            if isinstance(response, StreamingResponse):
                res_body = b""
                async for item in response.body_iterator:
                    res_body += item

                task = BackgroundTask(log_info, req_body, b"<streaming content>")
                return Response(
                    content=res_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                    background=task,
                )
            else:
                res_body = response.body
                response.background = BackgroundTask(log_with_label,
                            "Reply", sanitize_text(res_body.decode("utf-8").replace("\n", " ")))
                return response

        return custom_route_handler
