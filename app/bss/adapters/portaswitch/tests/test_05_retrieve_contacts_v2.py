"""
Tests for WT-1585 fix: GET /api/v2/user/contacts must resolve contacts by
extension number (ext) and additional numbers, not only by main number.

Run against local adapter:
    pytest test_05_retrieve_contacts_v2.py \
        --server-url http://127.0.0.1:4001 \
        --user 111000111 --password zzzxxx123
"""

import pytest
import requests


V2_PATH = "/api/v2/user/contacts"


@pytest.fixture
def contacts_data(valid_access_token, api_url):
    """Fetch the full contact list once and derive test fixtures from it."""
    headers = {"Authorization": f"Bearer {valid_access_token}"}
    resp = requests.get(
        api_url + V2_PATH,
        params={"items_per_page": 200},
        headers=headers,
    )
    assert resp.status_code == 200, f"Failed to fetch contacts: {resp.text}"
    items = resp.json()["items"]

    ext_contact = next(
        (c for c in items if c.get("numbers", {}).get("ext")), None
    )
    additional_contact = next(
        (c for c in items if c.get("numbers", {}).get("additional")), None
    )
    return {
        "items": items,
        "ext_contact": ext_contact,
        "additional_contact": additional_contact,
        "headers": headers,
        "base_url": api_url + V2_PATH,
    }


def _get(base_url, headers, **params):
    resp = requests.get(base_url, params=params, headers=headers)
    assert resp.status_code == 200, f"Unexpected {resp.status_code}: {resp.text}"
    return resp.json()


class TestPhoneNumbersLookup:
    """phone_numbers= parameter must find contacts by main, ext, and additional numbers."""

    def test_finds_by_main_number(self, contacts_data):
        ext_contact = contacts_data["ext_contact"]
        if not ext_contact:
            pytest.skip("No contact with ext found in this environment")

        main = ext_contact["numbers"]["main"]
        result = _get(contacts_data["base_url"], contacts_data["headers"], phone_numbers=main)

        assert result["pagination"]["items_total"] >= 1
        returned_mains = [i["numbers"]["main"] for i in result["items"]]
        assert main in returned_mains, (
            f"phone_numbers={main!r} (main) should return contact with that main number; got {returned_mains}"
        )

    def test_finds_by_ext_number(self, contacts_data):
        """Core regression: phone_numbers by short dial (ext) must find the owning account."""
        ext_contact = contacts_data["ext_contact"]
        if not ext_contact:
            pytest.skip("No contact with ext found in this environment")

        ext = ext_contact["numbers"]["ext"]
        main = ext_contact["numbers"]["main"]

        result = _get(contacts_data["base_url"], contacts_data["headers"], phone_numbers=ext)

        assert result["pagination"]["items_total"] >= 1, (
            f"phone_numbers={ext!r} (ext) returned 0 results — WT-1585 regression"
        )
        returned_mains = [i["numbers"]["main"] for i in result["items"]]
        assert main in returned_mains, (
            f"phone_numbers={ext!r} (ext) should return contact with main={main!r}; got {returned_mains}"
        )

    def test_ext_result_has_correct_ext_field(self, contacts_data):
        """The contact returned by ext lookup must itself report that ext value."""
        ext_contact = contacts_data["ext_contact"]
        if not ext_contact:
            pytest.skip("No contact with ext found in this environment")

        ext = ext_contact["numbers"]["ext"]
        result = _get(contacts_data["base_url"], contacts_data["headers"], phone_numbers=ext)

        returned_exts = [i["numbers"]["ext"] for i in result["items"]]
        assert ext in returned_exts, (
            f"phone_numbers={ext!r}: returned items have exts {returned_exts}, expected {ext!r}"
        )

    def test_finds_by_additional_number(self, contacts_data):
        """phone_numbers by an additional/alias number must return at least one result."""
        additional_contact = contacts_data["additional_contact"]
        if not additional_contact:
            pytest.skip("No contact with additional numbers in this environment")

        additional = additional_contact["numbers"]["additional"][0]
        result = _get(contacts_data["base_url"], contacts_data["headers"], phone_numbers=additional)

        assert result["pagination"]["items_total"] >= 1, (
            f"phone_numbers={additional!r} (additional) returned 0 results — WT-1585 regression"
        )
        # Either the original account or the account owning that number as primary is returned
        returned_mains = [i["numbers"]["main"] for i in result["items"]]
        returned_user_ids = [i["user_id"] for i in result["items"]]
        assert (
            additional in returned_mains
            or additional_contact["user_id"] in returned_user_ids
        ), (
            f"phone_numbers={additional!r}: expected to find account with that number; "
            f"got mains={returned_mains}"
        )

    def test_returns_empty_for_unknown_number(self, contacts_data):
        result = _get(contacts_data["base_url"], contacts_data["headers"],
                      phone_numbers="000000000000099")

        assert result["pagination"]["items_total"] == 0
        assert result["items"] == []

    def test_multiple_phone_numbers_at_once(self, contacts_data):
        """Multiple phone_numbers params must resolve independently and merge results."""
        items = contacts_data["items"]
        contacts_with_ext = [c for c in items if c["numbers"].get("ext")]
        if len(contacts_with_ext) < 2:
            pytest.skip("Need at least 2 contacts with ext for this test")

        c1, c2 = contacts_with_ext[0], contacts_with_ext[1]
        ext1, ext2 = c1["numbers"]["ext"], c2["numbers"]["ext"]

        result = _get(contacts_data["base_url"], contacts_data["headers"],
                      phone_numbers=[ext1, ext2])

        returned_mains = {i["numbers"]["main"] for i in result["items"]}
        assert c1["numbers"]["main"] in returned_mains, (
            f"ext {ext1!r} not resolved in multi-number lookup"
        )
        assert c2["numbers"]["main"] in returned_mains, (
            f"ext {ext2!r} not resolved in multi-number lookup"
        )


class TestSearchByExtNumber:
    """search= parameter must find contacts whose ext matches the query."""

    def test_search_by_ext_returns_matching_contact(self, contacts_data):
        """Core regression: search by extension number must find the owning account."""
        ext_contact = contacts_data["ext_contact"]
        if not ext_contact:
            pytest.skip("No contact with ext found in this environment")

        ext = ext_contact["numbers"]["ext"]
        main = ext_contact["numbers"]["main"]

        result = _get(contacts_data["base_url"], contacts_data["headers"], search=ext)

        assert result["pagination"]["items_total"] >= 1, (
            f"search={ext!r} (ext number) returned 0 results — WT-1585 regression"
        )
        returned_mains = [i["numbers"]["main"] for i in result["items"]]
        assert main in returned_mains, (
            f"search={ext!r} should return contact with main={main!r}; got {returned_mains}"
        )

    def test_search_by_ext_result_has_ext_field(self, contacts_data):
        ext_contact = contacts_data["ext_contact"]
        if not ext_contact:
            pytest.skip("No contact with ext found in this environment")

        ext = ext_contact["numbers"]["ext"]
        result = _get(contacts_data["base_url"], contacts_data["headers"], search=ext)

        returned_exts = [i["numbers"]["ext"] for i in result["items"]]
        assert ext in returned_exts, (
            f"search={ext!r}: returned items have exts {returned_exts!r}, expected {ext!r}"
        )

    def test_search_by_name_still_works(self, contacts_data):
        """Regression: existing name-based search must not be broken by the fix."""
        items = contacts_data["items"]
        # Find a contact with a non-empty alias_name to search by
        named = next(
            (c for c in items if c.get("alias_name") and len(c["alias_name"]) >= 3),
            None,
        )
        if not named:
            pytest.skip("No named contact found")

        name_fragment = named["alias_name"][:4]
        result = _get(contacts_data["base_url"], contacts_data["headers"], search=name_fragment)

        assert result["pagination"]["items_total"] >= 1, (
            f"search={name_fragment!r} (name fragment) returned 0 results"
        )

    def test_search_by_unknown_value_returns_empty(self, contacts_data):
        result = _get(contacts_data["base_url"], contacts_data["headers"],
                      search="xXxNoSuchContactxXx")

        assert result["pagination"]["items_total"] == 0
        assert result["items"] == []


class TestV2ContactsStructure:
    """Pagination and response structure sanity checks."""

    def test_pagination_fields_present(self, contacts_data):
        result = _get(contacts_data["base_url"], contacts_data["headers"],
                      page=1, items_per_page=5)

        pagination = result.get("pagination", {})
        assert "items_total" in pagination
        assert "items_per_page" in pagination
        assert "page" in pagination
        assert pagination["items_per_page"] == 5
        assert pagination["page"] == 1

    def test_items_per_page_respected(self, contacts_data):
        result = _get(contacts_data["base_url"], contacts_data["headers"],
                      page=1, items_per_page=3)

        assert len(result["items"]) <= 3

    def test_numbers_structure_in_all_items(self, contacts_data):
        result = _get(contacts_data["base_url"], contacts_data["headers"],
                      page=1, items_per_page=20)

        for item in result["items"]:
            nums = item.get("numbers")
            assert nums is not None, f"Contact {item.get('user_id')} missing numbers"
            assert "main" in nums
            assert "ext" in nums
            assert "additional" in nums
            assert isinstance(nums["additional"], list)
