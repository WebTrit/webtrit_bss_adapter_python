import requests
import pytest
from utils4testing import Attr, verify_attribute_in_json, compose_headers
import random

response = None

@pytest.mark.parametrize(
    "extra_path",
    [
        None,
        f"some/path/{random.randint(1, 10000)}",
        "42"
    ],
)
def test_public_method(api_url, custom_path, tenant_id, public_method, extra_path):
    global response, body  # so we can re-use it in later tests
    path = api_url + custom_path + '/' + public_method
    if extra_path:
        path += '/' + extra_path
    response = requests.post(
        path,
        json={"data": f"test of calling public method {random.randint(1, 10000)}"},
        headers=compose_headers(tenant_id=tenant_id,
                                other = dict(
                                    random_header = str(random.randint(1,10000))))
    )
    print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)



def test_private_method_fails_without_auth(api_url, custom_private_path, tenant_id, private_method):
    global response,response2, body, access_token  # so we can re-use it in later tests

    path = api_url + custom_private_path + '/' + private_method

    response2 = requests.post(
        path,
        json={ "msg": "calling private method without auth"},
        headers=compose_headers(tenant_id=tenant_id,
      
                                 other = dict(
                                    random_header = str(random.randint(1,10000))))
        # json = { }
    )

    print(response2.content)
    assert response2.status_code == 403

def test_private_method_fails_with_wrong_token(api_url, custom_private_path, tenant_id, private_method):
    global response,response2, body, access_token  # so we can re-use it in later tests

    path = api_url + custom_private_path + '/' + private_method

    response2 = requests.post(
        path,
        json={ "msg": "calling private method with wrong token"},
        headers=compose_headers(tenant_id=tenant_id,
                                access_token='WRONG-TOKEN',

                                other = dict(
                                    random_header = str(random.randint(1,10000))))
        # json = { }
    )

    print(response2.content)
    assert response2.status_code == 401


def test_do_login(api_url, login_path, username, password, tenant_id):
    global response, access_token, pp  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path,
        json={"login": username, "password": password},
        headers=compose_headers(tenant_id=tenant_id)
    )

    assert response.status_code == 200
    # memorize
    body = response.json()
    access_token = body.get("access_token", None)

@pytest.mark.parametrize(
    "extra_path",
    [
        None,
        f"some/path/{random.randint(1, 10000)}",
        "42"
    ],
)
def test_private_method(api_url, custom_private_path, tenant_id, private_method, extra_path):
    global response,response2, body, access_token  # so we can re-use it in later tests

    path = api_url + custom_private_path + '/' + private_method
    if extra_path:
        path += '/' + extra_path
    response2 = requests.post(
        path,
        headers=compose_headers(tenant_id=tenant_id,
                                access_token=access_token,
                                other = dict(
                                    random_header = str(random.randint(1,10000))))
        # json = { }
    )

    print(response2.content)
    assert response2.status_code == 200
    assert isinstance(body := response2.json(), dict)
