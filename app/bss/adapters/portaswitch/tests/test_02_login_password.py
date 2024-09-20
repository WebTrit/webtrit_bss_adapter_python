import requests


class TestLoginPassword:
    #: str: A value to be used while testing of the token refresh.
    refresh_token: str = ''
    #: str: A value to be used while testing of the session logout.
    access_token: str = ''

    @staticmethod
    def test_missing_data(api_url: str, login_path: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path, json={"abc": "123", "xyz": "12345"}
        )

        expected_json = [
            {'loc': ('body', 'login'), 'msg': 'field required', 'type': 'value_error.missing'},
            {'loc': ('body', 'password'), 'msg': 'field required', 'type': 'value_error.missing'}
        ]

        assert response.status_code == 422
        assert response.json()["details"]["reason"] == f"Input data validation error: {expected_json}"

    @staticmethod
    def test_incorrect_credentials(api_url: str, login_path: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path, json={"login": "hacker", "password": "12345"}
        )

        assert response.status_code == 401
        assert response.json()['message'] == 'User authentication error'

    def test_login(self, api_url: str, login_path: str, username: str, password: str, userid: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path,
            json={"login": username, "password": password},
        )

        body: dict = response.json()
        TestLoginPassword.refresh_token = body.get('refresh_token')
        TestLoginPassword.access_token = body.get('access_token')

        assert response.status_code == 200
        assert self.refresh_token
        assert self.access_token
        assert body['user_id'] == userid  # i_account

    @staticmethod
    def test_failed_refresh(api_url: str, login_path: str) -> None:
        token: str = 'hacked_token'
        response: requests.models.Response = requests.patch(
            api_url + login_path,
            json={"refresh_token": token},
        )

        assert response.status_code == 404
        assert response.json()['message'] == f'Invalid refresh token {token}'

    def test_refresh(self, api_url: str, login_path: str, username: str, userid: str) -> None:
        assert self.refresh_token

        response: requests.models.Response = requests.patch(
            api_url + login_path,
            json={"refresh_token": self.refresh_token},
        )
        old_refresh_token: str = self.refresh_token
        old_access_token: str = self.access_token

        body: dict = response.json()
        TestLoginPassword.refresh_token = body.get('refresh_token')
        TestLoginPassword.access_token = body.get('access_token')

        assert response.status_code == 200
        assert self.refresh_token and self.refresh_token != old_refresh_token
        assert self.access_token and self.access_token != old_access_token
        assert body.get('user_id') == userid  ## i_account

    @staticmethod
    def test_failed_logout(api_url: str, login_path: str):
        access_token: str = 'QQWWEE'
        response: requests.models.Response = requests.delete(
            api_url + login_path,
            headers={
                'Authorization': f"Bearer {access_token}"
            },
        )
        assert response.status_code == 404
        assert response.json()['message'] == f'Error closing the session {access_token}'

    def test_logout(self, api_url: str, login_path: str):
        access_token: str = self.access_token
        response: requests.models.Response = requests.delete(
            api_url + login_path,
            headers={
                'Authorization': f"Bearer {access_token}"
            },
        )
        assert response.status_code == 204
        assert response.content == b''

    def test_refresh2(self, api_url: str, login_path: str, username: str) -> None:
        response: requests.models.Response = requests.patch(
            api_url + login_path,
            json={"refresh_token": self.refresh_token},
        )

        assert self.refresh_token
        assert response.status_code == 404
        assert response.json()['message'] == f'Invalid refresh token {self.refresh_token}'
