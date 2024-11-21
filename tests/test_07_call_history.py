import requests
import pytest
import logging
import pprint
from dataclasses import dataclass
import json

from utils4testing import (Attr, verify_attribute_in_json, 
                           verify_attribute_value, compose_headers)


pp = pprint.PrettyPrinter(indent=4)

response = None
access_token = None


def test_do_login(api_url, login_path, username, password, tenant_id):
    global response, access_token  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path,
        json={"login": username, "password": password},
        headers=compose_headers(tenant_id=tenant_id)
    )
    assert response.status_code == 200
    # memorize
    body = response.json()
    access_token = body.get("access_token", None)


response2 = None


def test_call_history(api_url, call_history_path, tenant_id):
    global response2, access_token
    headers = {"Authorization": "Bearer " + access_token,
                }

    response2 = requests.get(
        api_url + call_history_path,
        headers=compose_headers(tenant_id=tenant_id,
                                access_token=access_token,
                                other = { "X-Request-ID": "test" + call_history_path + "1"} ),
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

        Attr(name="connect_time", type=str, mandatory=True),
        Attr(name="callee", type=str, mandatory=True),
        Attr(name="caller", type=str, mandatory=True),
        Attr(name="direction", type=str, mandatory=True),
        Attr(name="status", type=str, mandatory=True),
        Attr(name="duration", type=type(0)),
        Attr(name="disconnected_reason", type=str),
        Attr(name="recording_id", type=str),
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

@pytest.mark.parametrize(
    "page",
    [
        { "page": 1, "items_per_page": 40, "items_total": 250, "items": 40}, # first page
        { "page": 5, "items_per_page": 40, "items_total": 250, "items": 40}, # middle page
        { "page": 7, "items_per_page": 40, "items_total": 250, "items": 10}, # last page
        { "page": 8, "items_per_page": 40, "items_total": 250, "items": 0}, # empty page
    ],
)
def test_call_history_pagination(api_url, call_history_path, page):
    global response2, access_token
    headers = {"Authorization": "Bearer " + access_token}

    response2 = requests.get(
        api_url + call_history_path,
        headers=headers,
        params = { "time_from": "1974-01-01 00:00:00",
                    "items_per_page": page["items_per_page"],
                    "page": page["page"]
                    }
        # json = { }
    )
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = None
    print(f"response: {pp.pformat(body)}")
    assert response2.status_code == 200
    assert isinstance(body, dict)
    assert 'items' in body and isinstance(body['items'], list)
    assert 'pagination' in body and isinstance(body['pagination'], dict)
    pagination = body['pagination']
    assert pagination["page"] == page["page"]
    assert pagination["items_per_page"] == page["items_per_page"]
    assert pagination["items_total"] == page["items_total"]
    assert len(body['items']) == page["items"]
    # we got an object (dict)
