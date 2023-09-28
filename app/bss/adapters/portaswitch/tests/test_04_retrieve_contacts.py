import requests


class TestRetrieveContacts:

    #: str: The token used to perform API requests.
    access_token: str = ''

    def test_login(self, api_url: str, login_path: str, username: str, password: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path,
            json = {"login": username, "password": password},
        )
        assert response.status_code == 200

        body: dict = response.json()
        TestRetrieveContacts.access_token = body.get('access_token')
        assert self.access_token

    def test_absent_token(self, api_url: str, contacts_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + contacts_path,
            headers = {},
        )
        body: dict = response.json()

        assert response.status_code == 403
        assert body.get('detail') == 'Not authenticated'

    def test_invalid_token(self, api_url: str, contacts_path: str) -> None:
        access_token: str = self.access_token + 'qq'

        response: requests.models.Response = requests.get(
            api_url + contacts_path,
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 401

        body: dict = response.json()

        assert body.get('code') == 'authorization_header_missing'
        assert body.get('details').get('reason') == f'Invalid access token {access_token}'

    def test_contacts_retrieved(self, api_url: str, contacts_path: str) -> None:
        access_token: str = self.access_token

        response: requests.models.Response = requests.get(
            api_url + contacts_path,
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 200

        body: dict = response.json()
        items: list = body.get('items')
        assert items is not None
        assert len(items) is not None

        item = items[0]

        assert item.get('alias_name') is not None
        assert item.get('company_name') is not None
        assert item.get('email') is not None
        assert item.get('first_name') is not None
        assert item.get('last_name') is not None
        assert item.get('numbers') is not None
        assert item.get('numbers').get('additional') is not None
        assert item.get('numbers').get('ext') is not None
        assert item.get('numbers').get('main') is not None
        assert item.get('sip_status')is not None
