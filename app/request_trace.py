from fastapi import Response, Request
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse
from fastapi.routing import APIRoute

# from starlette.types import Message
from typing import Callable
import logging
import pprint
import json

pp = pprint.PrettyPrinter(indent=4)

# logger = logging.getLogger(__name__)


def log_formatted_json(label: str, text):
    """Take JSON (as byte-string) and pretty-print it to the log"""
    if len(text) == 0:
        logging.info(f"{label}: Empty")
        return

    try:
        json_data = text.decode("utf-8")
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        logging.info(f"{label}: Invalid JSON structure {e}")
        return
    formatted = pp.pformat(data) if False else str(data)
    logging.info(f"{label}: {formatted}")


def log_info(req_body, res_body):
    log_formatted_json("Request body", req_body)
    log_formatted_json("Reply body", res_body)


class RouteWithLogging(APIRoute):
    """Custom route class that logs request and response bodies """
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            req_body = await request.body()
            response = await original_route_handler(request)

            if isinstance(response, StreamingResponse):
                res_body = b""
                async for item in response.body_iterator:
                    res_body += item

                task = BackgroundTask(log_info, req_body, res_body)
                return Response(
                    content=res_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                    background=task,
                )
            else:
                res_body = response.body
                response.background = BackgroundTask(log_info, req_body, res_body)
                return response

        return custom_route_handler
