from fastapi import Response, Request, HTTPException
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse
from fastapi.routing import APIRoute

# from starlette.types import Message
from typing import Callable
import logging
import pprint
import json
import uuid

pp = pprint.PrettyPrinter(indent=4)

# logger = logging.getLogger(__name__)

def get_request_id(request: Request):
    for id in [
        request.headers.get('X-Request-ID', None),
        request.headers.get('X-Cloud-Trace-Context', None),
    ]:
        if id is not None:
            return id
    return 'WEBTRIT'+str(uuid.uuid4())

def log_formatted_json(label: str, text):
    """Take JSON (as byte-string) and pretty-print it to the log"""
    # not very efficient, skip for now
    try:
        json_data = text.decode("utf-8")
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        logging.info(f"{label}: Invalid JSON structure {e}")
        return
    formatted = pp.pformat(data) if False else str(data)
    logging.info(f"{label}: {formatted}")

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
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            req_body = await request.body()
            req_body = req_body.decode("utf-8")
            req_id = get_request_id(request)
            log_with_label(f"{request.method} request to {request.url.path} " + \
#                           added by the logger
#                           f"'X-Request-ID': {req_id} " + \
                           f"'X-WebTrit-Tenant-ID': {request.headers.get('X-WebTrit-Tenant-ID')}",
                           f"body: {req_body}"
                        )
            try:
                response = await original_route_handler(request)
            except HTTPException as http_exc:
                logging.error(f"HTTP exception {http_exc.status_code} {http_exc.detail}")
                raise http_exc
            except Exception as e:
                logging.error(f"Exception: {e}")
                # we assume the error was already logged by the original_route_handler
                raise e

            if isinstance(response, StreamingResponse):
                res_body = b""
                async for item in response.body_iterator:
                    res_body += item

                task = BackgroundTask(log_req_and_reply, req_body, res_body)
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
                                                    f"Reply to {request.url.path}",
                                                    res_body.decode("utf-8"))
                return response

        return custom_route_handler
