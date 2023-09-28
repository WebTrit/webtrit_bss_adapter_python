import requests


class TestRetrieveCalls:

    #: str: The token used to perform API requests.
    access_token: str = ''

    def test_login(self, api_url: str, login_path: str, username: str, password: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path,
            json = {"login": username, "password": password},
        )
        assert response.status_code == 200

        body: dict = response.json()
        TestRetrieveCalls.access_token = body.get('access_token')
        assert self.access_token

    def test_absent_token(self, api_url: str, history_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + history_path,
            headers = {},
        )
        body: dict = response.json()

        assert response.status_code == 403
        assert body.get('detail') == 'Not authenticated'

    def test_invalid_token(self, api_url: str, history_path: str) -> None:
        access_token: str = 'qq'

        response: requests.models.Response = requests.get(
            api_url + history_path,
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 401

        body: dict = response.json()

        assert body.get('code') == 'authorization_header_missing'
        assert body.get('details').get('reason') == f'Invalid access token {access_token}'

    def test_contacts_retrieved(self, api_url: str, history_path: str) -> None:
        access_token: str = self.access_token

        response: requests.models.Response = requests.get(
            api_url + history_path,
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 200


        body: dict = response.json()
        pagination: dict = body.get('pagination')

        assert pagination.get('items_per_page') is not None
        assert pagination.get('items_total') is not None
        assert pagination.get('page') is not None

        items: list = body.get('items')
        assert items is not None
        assert len(items) is not None

        item: dict = items[0]

        assert item.get('callee') is not None
        assert item.get('caller') is not None
        assert item.get('connect_time') is not None
        assert item.get('direction') is not None
        assert item.get('disconnect_reason') is not None
        assert item.get('disconnect_time') is not None
        assert item.get('duration') is not None
        assert item.get('recording_id') is not None
        assert item.get('status') is not None
