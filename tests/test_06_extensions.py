import requests
import pytest
import datetime
import logging
import pprint
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
    try:
        body = response.json()
    except json.JSONDecodeError:
        body = {}
    access_token = body.get("access_token", None)


response2 = None


def test_extensions(api_url, extensions_path):
    global response2, body, access_token
    response2 = requests.get(
        api_url + extensions_path,
        headers={"Authorization": "Bearer " + access_token,
                  },
    )

    logging.info("response:" + response2.content.decode("utf-8"))
    assert response2.status_code == 200
    # we got a list
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = {}
    logging.warning("Reply from the server:" + pp.pformat(body))

    assert isinstance(body, dict)
    assert 'items' in body


# required response attributes
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="company_name", type=type("")),
        Attr(name="email", type=type("")),
        Attr(name="firstname", type=type("")),
        Attr(name="lastname", type=type("")),
        Attr(name="numbers", type=type({})),
        Attr(name="sip", type=type({}), mandatory=True),
    ],
)
def test_extensions_elements(api_url, extensions_path, attr):
    global body

    for x in body["items"]:
        # verify the attribute in each returned element
        verify_attribute_in_json(attr, x)

@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="main", type=type(""), mandatory=True),
        Attr(name="ext", type=type("")),
        Attr(name="additional", type=type([]))
    ],
)
def test_extension_numbers(api_url, extensions_path, attr):
    global body

    for x in body["items"]:
         # verify the attribute in each returned element
        numbers = x["numbers"]
        logging.warning("numbers:" + pp.pformat(numbers))
        verify_attribute_in_json(attr, numbers)
  
