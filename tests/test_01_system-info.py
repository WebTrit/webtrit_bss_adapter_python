import requests
import pytest


def test_get_system_info_200(api_url, system_info_path):
    print(f"sending req to {api_url + system_info_path}")
    response = requests.get(api_url + system_info_path)
    assert response.status_code == 200


def test_get_system_info_json(api_url, system_info_path):
    response = requests.get(api_url + system_info_path)
    assert response.headers["Content-Type"] == "application/json" and response.json()


# required response attributes
@pytest.mark.parametrize(
    "attr, expected", [("version", "0.0.1"), ("name", ""), ("supported", list())]
)
def test_get_system_info_attr(api_url, system_info_path, attr, expected):
    response = requests.get(api_url + system_info_path)
    body = response.json()
    assert attr in body
    assert body[attr]  # not empty
    assert type(expected) == type(body[attr])  # same type
    # if the value is provided - ensure it matches
    if expected:
        assert body[attr] == expected


@pytest.mark.parametrize(
    "attr, expected",
    [
#        ("otpSignin", ""),
        ("passwordSignin", ""),
 #       ("callHistory", ""),
        ("extensions", ""),
    ],
)
def test_get_system_info_supported(api_url, system_info_path, attr, expected):
    response = requests.get(api_url + system_info_path)
    body = response.json()
    supported = body["supported"]
    assert attr in supported
