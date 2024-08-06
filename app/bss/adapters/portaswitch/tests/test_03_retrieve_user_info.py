import requests


class TestRetrieveUserInfo:
    def test_absent_token(self, api_url: str, user_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + user_path,
            headers={},
        )

        assert response.status_code == 403
        assert response.json()['message'] == 'Server error: Not authenticated'

    def test_invalid_token(self, invalid_access_token: str, api_url: str, user_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + user_path,
            headers={
                'Authorization': f"Bearer {invalid_access_token}"
            },
        )

        body: dict = response.json()

        assert response.status_code == 401
        assert body['message'] == f'Invalid access token {invalid_access_token}'

    def test_user_retrieved(self, valid_access_token: str, username: str, api_url: str, user_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + user_path,
            headers={
                'Authorization': f"Bearer {valid_access_token}"
            },
        )

        body: dict = response.json()

        assert response.status_code == 200
        assert body.get('alias_name') is None
        assert body.get('balance') is not None
        assert body.get('balance').get('amount') is not None
        assert body.get('balance').get('balance_type') is not None
        assert body.get('balance').get('currency') is not None
        assert body.get('company_name') is not None
        assert body.get('email') is not None
        assert body.get('numbers') is not None
        assert body.get('numbers').get('main') == username
        assert body.get('sip').get('auth_username') == username
        assert body.get('sip').get('display_name') is not None
        assert body.get('sip').get('password') is not None
        assert body.get('sip').get('sip_server') is not None
        assert body.get('sip').get('sip_server').get('force_tcp') is not None
        assert body.get('sip').get('sip_server').get('host') is not None
        assert body.get('sip').get('sip_server').get('port') is not None
        assert body.get('sip').get('username') == username
        assert body.get('status') is not None
        assert body.get('time_zone') is not None
