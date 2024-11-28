import logging
import os
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

# Add context variable for request ID
current_request_id = contextvars.ContextVar('current_request_id', default="STARTUP")

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
    logging.info(f"{label}: {text}")
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
            req_body = req_body.decode("utf-8").replace("\n", " ")

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
                            "Reply", err_response.body.decode("utf-8").replace("\n", " "))
                return err_response
            except Exception as e:
                logging.error(f"Application error: {e} {traceback.format_exc()}")
                return JSONResponse(
                                        status_code=500,
                                        content=dict(
                                            message = f"Server error: {e}",
                                            trace = traceback.format_exc()
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
                            "Reply", res_body.decode("utf-8").replace("\n", " "))
                return response

        return custom_route_handler
