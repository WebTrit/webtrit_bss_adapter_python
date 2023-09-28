
import requests


class TestRetrieveUserInfo:

    #: str: The token used to perform API requests.
    access_token: str = ''

    def test_login(self, api_url: str, login_path: str, username: str, password: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path,
            json = {"login": username, "password": password},
        )
        assert response.status_code == 200

        body: dict = response.json()
        TestRetrieveUserInfo.access_token = body.get('access_token')
        assert self.access_token

    def test_absent_token(self, api_url: str, user_path: str) -> None:

        response: requests.models.Response = requests.get(
            api_url + user_path,
            headers = {},
        )
        body: dict = response.json()

        assert response.status_code == 403
        assert body.get('detail') == 'Not authenticated'

    def test_invalid_token(self, api_url: str, user_path: str) -> None:
        access_token: str = 'qq'

        response: requests.models.Response = requests.get(
            api_url + user_path,
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 401

        body: dict = response.json()

        assert body.get('code') == 'authorization_header_missing'
        assert body.get('details').get('reason') == f'Invalid access token {access_token}'

    def test_user_retrieved(self, api_url: str, user_path: str) -> None:
        access_token: str = self.access_token

        response: requests.models.Response = requests.get(
            api_url + user_path,
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 200

        body: dict = response.json()

        assert body.get('alias_name') is not None
        assert body.get('balance') is not None
        assert body.get('balance').get('amount') is not None
        assert body.get('balance').get('balance_type') is not None
        assert body.get('balance').get('credit_limit') is not None
        assert body.get('balance').get('currency') is not None
        assert body.get('company_name') is not None
        assert body.get('email') is not None
        assert body.get('first_name') is not None
        assert body.get('last_name') is not None
        assert body.get('numbers') is not None
        assert body.get('numbers') is not None
        assert body.get('numbers').get('additional') is not None
        assert body.get('numbers').get('ext') is not None
        assert body.get('numbers').get('main') is not None
        assert body.get('sip').get('auth_username') is not None
        assert body.get('sip').get('display_name') is not None
        assert body.get('sip').get('password') is not None
        assert body.get('sip').get('sip_server') is not None
        assert body.get('sip').get('sip_server').get('force_tcp') is not None
        assert body.get('sip').get('sip_server').get('host') is not None
        assert body.get('sip').get('sip_server').get('port') is not None
        assert body.get('sip').get('username') is not None
        assert body.get('status') is not None
        assert body.get('time_zone') is not None
