import requests
import pytest
import logging
import pprint
from dataclasses import dataclass
import json

from utils4testing import Attr, verify_attribute_in_json, verify_attribute_value


pp = pprint.PrettyPrinter(indent=4)

response = None
access_token = None


def test_do_login(api_url, login_path, username, password):
    global response, access_token  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path, json={"login": username, "password": password}
    )
    assert response.status_code == 200
    # memorize
    body = response.json()
    access_token = body.get("access_token", None)


response2 = None


def test_call_history(api_url, call_history_path):
    global response2, access_token
    headers = {"Authorization": "Bearer " + access_token}

    response2 = requests.get(
        api_url + call_history_path,
        headers=headers,
        # json = { }
    )
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = None
    logging.info("response:" + pp.pformat(body))
    assert response2.status_code == 200
    # we got an object (dict)

    assert isinstance(body, dict)
    verify_attribute_in_json(Attr(name="items", type=type([]), mandatory=True), body)
    verify_attribute_in_json(Attr(name="pagination", type=type({}), mandatory=True), body)


# required response attributes
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="call", type=type({})),
        Attr(name="call_recording_id", type=type("")),
        Attr(name="call_start_time", type=type(""), mandatory=True),
        Attr(name="callee", type=type(""), mandatory=True),
        Attr(name="caller", type=type(""), mandatory=True),
        Attr(name="duration", type=type(0), mandatory=True),
    ],
)
def test_cdrs(api_url, call_history_path, attr):
    global response2, pp
    try:
        items = response2.json()["items"]
    except json.JSONDecodeError as e:
        items = []

    logging.warning("Items:" + pp.pformat(items))

    for x in items:
        verify_attribute_in_json(attr, x)
