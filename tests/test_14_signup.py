import requests
import pytest
import logging
import json
from utils4testing import Attr, verify_attribute_in_json, compose_headers
import random

response = None

email = f"andrew-rnd{random.randint(100,10000)}@asgard.ti.cz"
user_info = {
            "email": email,
            "client_data": {
                "device": "iPhone"
            }
        }

def test_create(api_url, signup_path):
    global response, body, otp_id, tenant_id  # so we can re-use it in later tests
    response = requests.post(
        api_url + signup_path, json= user_info 
    )
    print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)
    assert (otp_id := body.get("otp_id", None)) is not None
    assert (tenant_id := body.get("tenant_id", None)) is not None    

def test_otp_login1(api_url, otp_verify_path, otp_code):
    global otp_id, tenant_id

    response2 = requests.post(
        api_url + otp_verify_path, json={"otp_id": otp_id, "code": otp_code},
        headers = compose_headers(tenant_id = tenant_id)
    )
    assert response2.status_code == 200

def test_postcreate_otplogin(api_url, signup_path):
    global response, body, otp_id  # so we can re-use it in later tests
    response = requests.post(
        api_url + signup_path, json= user_info
    )
    print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)
    assert (otp_id := body.get("otp_id", None)) is not None

def test_otp_login2(api_url, otp_verify_path, otp_code):
    global otp_id, tenant_id

    response2 = requests.post(
        api_url + otp_verify_path, json={"otp_id": otp_id, "code": otp_code},
        headers = compose_headers(tenant_id = tenant_id)
    )
    assert response2.status_code == 200

def test_obtain_invite_token(api_url, signup_path):
    global response, body, tenant_id  # so we can re-use it in later tests
    response = requests.post(
        api_url + signup_path, json= {
            "action": "invite",
            "tenant_id": tenant_id,
            "email": email,
        },
        headers = compose_headers(tenant_id = tenant_id)
    )
    print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)
    assert body.get("status", None) == "Ok"
    assert (api_token := body.get("api_token", None)) is not None

