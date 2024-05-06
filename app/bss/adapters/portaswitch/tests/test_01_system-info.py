import requests


def test_system_info(api_url: str, system_info_path: str) -> None:
    response: requests.models.Response = requests.get(api_url + system_info_path)

    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json' and response.json()

    body: dict = response.json()

    assert body['name'] == 'PortaSwitch adapter'
    assert body['version'] == '0.0.1'
    assert set(body['supported']) == {'otpSignin', 'passwordSignin', 'callHistory', 'recordings', 'extensions'}
