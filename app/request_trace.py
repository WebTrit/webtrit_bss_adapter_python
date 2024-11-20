from fastapi import Response, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse
from fastapi.routing import APIRoute
from report_error import WebTritErrorException

# from starlette.types import Message
from typing import Callable
import logging
# import pprint
# import json
import uuid
import os
from contextvars import ContextVar
import traceback

# pp = pprint.PrettyPrinter(indent=4)

request_id: ContextVar[str] = ContextVar('request_id', default='')
request_id.set('STARTUP')

class CustomFormatter(logging.Formatter):
    def format(self, record):
        record.request_id = request_id.get()  # Add your custom field here
        return super().format(record)


# Create a custom formatter instance
if not os.environ.get('PORT'):
    # we are running locally so it is useful to add timestamps
    # since when running in GCP, logs already have timestamps
    log_prefix='[%(asctime)s] %(levelname)s '
else:
    # cloud debug
    log_prefix='%(levelname)s '

log_formatter = CustomFormatter(fmt = log_prefix +'RQ-ID:%(request_id)s %(message)s')

def get_request_id(request: Request):
    for id in [
        request.headers.get('X-Request-ID', None),
        request.headers.get('X-Cloud-Trace-Context', None),
    ]:
        if id is not None:
            return id
    return 'WEBTRIT'+str(uuid.uuid4())

# def log_formatted_json(label: str, text):
#     """Take JSON (as byte-string) and pretty-print it to the log"""
#     # not very efficient, skip for now
#     try:
#         json_data = text.decode("utf-8")
#         data = json.loads(json_data)
#     except json.JSONDecodeError as e:
#         logging.info(f"{label}: Invalid JSON structure {e}")
#         return
#     formatted = pp.pformat(data) if False else str(data)
#     logging.info(f"{label}: {formatted}")

def log_with_label(label: str, text):
    if len(text) == 0:
        logging.info(f"{label}: Empty")
        return
    logging.info(f"{label}: {text}")
    return

def log_req_and_reply(req_body: str, res_body: str):
    log_with_label('Request', req_body)
    log_with_label('Reply', res_body)

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
    
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            request_id.set(get_request_id(request))
            req_body = await request.body()
            req_body = req_body.decode("utf-8")
            if len(req_body) == 0:
                req_body = "<empty>"
            log_with_label(f"{request.method} request to {request.url.path} " + \
                            self.add_headers_to_log(request),
                            f"body: {req_body}"
                        )
            try:
                response = await original_route_handler(request)
            except RequestValidationError as validation_exc:
                # errors when invalid input data is provided
                err_response = WebTritErrorException(status_code=422,
                                                     error_message = "Input data validation error: " + 
                                                            str(validation_exc.errors()),
                                                     path = request.url.path,
                                                     ).response()

                logging.error(f"Validation exception {validation_exc.errors()}")
                return err_response
            except WebTritErrorException as e:
                # an error produced by our own code 
                logging.error(f"App-generated exception {e.status_code} {e.error_message}")
                err_response = e.response()
                err_response.background = BackgroundTask(log_with_label,
                                                    f"Reply to {request.method} {request.url.path} " + \
                                                    f"http code {e.status_code}",
                                                    err_response.body.decode("utf-8"))
                return err_response
            except HTTPException as http_exc:
                if hasattr(http_exc, 'response'):
                    err_response = http_exc.response()
                else:
                    err_response = WebTritErrorException(
                                        status_code=http_exc.status_code,
                                        error_message = "Server error: " +
                                            http_exc.detail if hasattr(http_exc, 'detail') else "Unknown error",
                                            path=request.url.path,
                    ).response()
                logging.error(f"HTTP exception {http_exc.status_code} {http_exc.detail}")
                err_response.background = BackgroundTask(log_with_label,
                                                    f"Reply to {request.method} {request.url.path} " + \
                                                    f"http code {http_exc.status_code}",
                                                    err_response.body.decode("utf-8"))
                return err_response
            except Exception as e:
                logging.error(f"Application error: {e} {traceback.format_exc()}")
                # we assume the error was already logged by the original_route_handler
                raise HTTPException(
                    status_code=500, 
                    detail=f"An error {e} occurred")


            if isinstance(response, StreamingResponse):
                task = BackgroundTask(log_req_and_reply, req_body,
                                      "<binary/streaming content>")
                return response
            else:
                res_body = response.body
                response.background = BackgroundTask(log_with_label,
                                                    f"Reply to {request.method} {request.url.path}",
                                                    res_body.decode("utf-8"))
                return response

        return custom_route_handler
