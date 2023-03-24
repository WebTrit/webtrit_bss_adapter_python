import requests
import pytest
import datetime


def test_failed_login(api_url, login_path):
    response = requests.post(
        api_url + login_path, json={"login": "hacker", "password": "12345"}
    )
    assert response.status_code == 401


response = None


def test_login(api_url, login_path, username, password):
    global response  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path, json={"login": username, "password": password}
    )
    assert response.status_code == 200


# required response attributes
@pytest.mark.parametrize(
    "attr, expected",
    [
        ("access_token", ""),
        ("expires_at", ""),
        ("refresh_token", None),
        ("user_id", pytest.lazy_fixture("username")),
    ],
)
def test_login_attr(api_url, login_path, attr, expected):
    global response
    body = response.json()

    # if the value is provided - ensure it matches
    if expected:
        assert attr in body
        assert body[attr]  # not empty
        assert type(expected) == type(body[attr])  # same type
        assert body[attr] == expected


response2 = None


def test_refresh(api_url, login_path):
    global response, response2
    body = response.json()

    response2 = requests.put(
        api_url + login_path,
        json={"refresh_token": body["refresh_token"], "user_id": body["user_id"]},
    )
    print(response2.json())
    assert response2.status_code == 200


# required response attributes
@pytest.mark.parametrize(
    "attr, expected",
    [
        ("access_token", ""),
        ("expires_at", ""),
        ("refresh_token", None),
        ("user_id", pytest.lazy_fixture("username")),
    ],
)
def test_refresh_attr(api_url, login_path, attr, expected):
    global response2
    body = response2.json()

    # if the value is provided - ensure it matches
    if expected:
        assert attr in body
        assert body[attr]  # not empty
        assert type(expected) == type(body[attr])  # same type
        assert body[attr] == expected
