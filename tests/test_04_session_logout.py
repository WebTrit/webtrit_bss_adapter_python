import requests
import pytest
import datetime

response = None
access_token = None


def test_login(api_url, login_path, username, password):
    global response, access_token  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path, json={"login": username, "password": password}
    )
    assert response.status_code == 200
    body = response.json()
    access_token = body.get("access_token", None)


response2 = None


def test_logout(api_url, login_path):
    global access_token

    response2 = requests.delete(
        api_url + login_path,
        headers={"Authorization": "Bearer " + access_token},
        json={},
    )
    assert response2.status_code == 204
