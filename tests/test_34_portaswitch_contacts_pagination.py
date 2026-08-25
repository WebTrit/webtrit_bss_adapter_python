"""Pagination invariants of PortaSwitchAdapter.retrieve_contacts_v2 in ACCOUNTS mode (WT-1774).

The adapter used to offset PortaBilling's get_account_list by a position counted in
post-filter contacts, and to report PortaBilling's unfiltered `total` as items_total.
Both are checked here against a fake AdminAPI that scatters filtered-out rows
(blocked / dual-version SOURCE / the requesting user) through the raw account list.
"""
import math
import os
import sys

import pytest

_app_path = os.path.join(os.path.dirname(__file__), '..', 'app')
sys.path.insert(0, _app_path)

# PortaSwitchSettings is instantiated at import time and its four URL/credential
# fields are mandatory; supply throwaway values before importing the adapter.
os.environ.setdefault('PORTASWITCH_ADMIN_API_URL', 'https://pbx.example.com')
os.environ.setdefault('PORTASWITCH_ACCOUNT_API_URL', 'https://pbx.example.com')
os.environ.setdefault('PORTASWITCH_ADMIN_API_LOGIN', 'admin')
os.environ.setdefault('PORTASWITCH_ADMIN_API_TOKEN', 'token')
os.environ.setdefault('PORTASWITCH_SIP_SERVER_HOST', '1.2.3.4')

from bss.adapters.portaswitch.adapter import PortaSwitchAdapter
from bss.adapters.portaswitch.config import PortaSwitchSettings
from bss.adapters.portaswitch.types import PortaSwitchContactsSelectingMode
from bss.types import SessionInfo, UserInfo

I_CUSTOMER = 100
CURRENT_I_ACCOUNT = 5001
MAX_API_LIMIT = 1000


def make_account(i_account, **overrides):
    account = {
        "i_account": i_account,
        "i_customer": I_CUSTOMER,
        "id": f"1000{i_account}",
        "extension_name": f"user{i_account}",
        "extension_id": str(i_account % 1000),
        "firstname": "First",
        "lastname": f"Last{i_account}",
        "email": f"user{i_account}@example.com",
        "sip_status": 1,
        "status": "active",
        "alias_list": [],
    }
    account.update(overrides)
    return account


def build_raw_accounts(count, blocked_every=4, source_every=7):
    """Raw PortaBilling rows: the requesting user plus `count` others, with
    blocked and dual-version-SOURCE rows scattered through the list."""
    raw = [make_account(CURRENT_I_ACCOUNT)]
    for n in range(count):
        i_account = 6000 + n
        overrides = {}
        if blocked_every and n % blocked_every == 0:
            overrides["status"] = "blocked"
        elif source_every and n % source_every == 0:
            overrides["dual_version_system"] = "source"
        raw.append(make_account(i_account, **overrides))
    return raw


class FakeAdminAPI:
    """Serves get_account_list with PortaBilling's LIMIT/OFFSET semantics over the
    raw (unfiltered) row list, and reports the raw total the way PortaBilling does."""

    def __init__(self, accounts_by_customer, chunk_overlap=0, scramble=False, branch_customers=()):
        self.accounts_by_customer = accounts_by_customer
        self.chunk_overlap = chunk_overlap
        self.scramble = scramble
        self.branch_customers = list(branch_customers)
        self.calls = []

    def _rows(self, i_customer):
        rows = self.accounts_by_customer[i_customer]
        if not self.scramble:
            return rows
        # PortaBilling is sent no ORDER BY, so the row order of one query is not
        # guaranteed to match the next. Reverse the list to model the worst case:
        # every window a caller reads is ordered the opposite way from the fixture.
        return rows[::-1]

    async def get_account_list(self, i_customer, limit=None, offset=0, **search_params):
        self.calls.append({"i_customer": i_customer, "limit": limit, "offset": offset, **search_params})
        assert limit is None or limit <= MAX_API_LIMIT, "PortaBilling rejects limit > 1000"
        rows = self._rows(i_customer)
        # Simulate an unstable row order between separate LIMIT/OFFSET queries: a
        # later chunk re-serves the tail of the previous one.
        start = max(0, offset - self.chunk_overlap) if offset else 0
        window = rows[start:start + limit] if limit else rows[start:]
        return {"account_list": window, "total": len(rows)}

    async def get_customer_info(self, i_customer):
        # i_office_type 3 == main office (has branches), 1 == standalone customer
        if self.branch_customers:
            return {"customer_info": {"i_office_type": 3}}
        return {"customer_info": {"i_office_type": 1}}

    async def get_customer_list(self, main_i_customer):
        return {"customer_list": [{"i_customer": c} for c in self.branch_customers]}

    async def get_extensions_list(self, i_customer, **kwargs):
        extensions = [
            {"i_account": a["i_account"], "id": a.get("extension_id", "")}
            for rows in self.accounts_by_customer.values()
            for a in rows
            if a.get("extension_id")
        ]
        return {"extensions_list": extensions}


class FakeAccountAPI:
    def __init__(self, i_account, i_customer):
        self._info = {"i_account": i_account, "i_customer": i_customer}

    async def get_account_info(self, access_token):
        return {"account_info": self._info}


def make_adapter(raw_accounts, custom_contacts=(), skip_without_extension=False,
                 chunk_overlap=0, scramble=False, branch_accounts=None):
    settings = PortaSwitchSettings(
        ADMIN_API_URL='https://pbx.example.com',
        ACCOUNT_API_URL='https://pbx.example.com',
        ADMIN_API_LOGIN='admin',
        ADMIN_API_TOKEN='token',
        SIP_SERVER_HOST='1.2.3.4',
        CONTACTS_SELECTING=PortaSwitchContactsSelectingMode.ACCOUNTS,
        CONTACTS_SKIP_WITHOUT_EXTENSION=skip_without_extension,
        CONTACTS_CUSTOM=list(custom_contacts),
    )
    # Bypass __init__: it builds HTTP connectors, OTP storage and failover state,
    # none of which retrieve_contacts_v2 touches on the ACCOUNTS path.
    adapter = object.__new__(PortaSwitchAdapter)
    adapter._portaswitch_settings = settings
    by_customer = {I_CUSTOMER: raw_accounts}
    by_customer.update(branch_accounts or {})
    adapter._admin_api = FakeAdminAPI(
        by_customer,
        chunk_overlap=chunk_overlap,
        scramble=scramble,
        branch_customers=list((branch_accounts or {}).keys()),
    )
    adapter._account_api = FakeAccountAPI(CURRENT_I_ACCOUNT, I_CUSTOMER)
    return adapter


async def fetch_page(adapter, page, items_per_page):
    session = SessionInfo(user_id=str(CURRENT_I_ACCOUNT), access_token='tok', refresh_token='ref')
    user = UserInfo(user_id=str(CURRENT_I_ACCOUNT))
    return await adapter.retrieve_contacts_v2(session, user, page=page, items_per_page=items_per_page)


async def walk_all_pages(adapter, items_per_page):
    """Page through the directory the way the dialer does — driven by items_total."""
    first_items, total = await fetch_page(adapter, 1, items_per_page)
    pages = [first_items]
    for page in range(2, math.ceil(total / items_per_page) + 1):
        items, page_total = await fetch_page(adapter, page, items_per_page)
        assert page_total == total, f"items_total changed on page {page}: {page_total} != {total}"
        pages.append(items)
    return pages, total


def keys(items):
    return [item.user_id.root if hasattr(item.user_id, 'root') else item.user_id for item in items]


# --- items_total describes what the adapter actually delivers ---------------

@pytest.mark.asyncio
async def test_items_total_equals_deliverable_count():
    raw = build_raw_accounts(90)
    deliverable = sum(
        1 for a in raw
        if a["i_account"] != CURRENT_I_ACCOUNT
        and a.get("status") != "blocked"
        and a.get("dual_version_system") != "source"
    )
    assert deliverable < len(raw), "the fixture must contain filtered-out rows"

    for items_per_page in (15, 25, 40):
        _, total = await fetch_page(make_adapter(raw), 1, items_per_page)
        assert total == deliverable, f"items_per_page={items_per_page}"


# --- pages are disjoint, gap-free, and there is no empty trailing page ------

@pytest.mark.asyncio
async def test_pages_are_disjoint_and_cover_everything():
    raw = build_raw_accounts(90)

    for items_per_page in (15, 25, 40, 1000):
        pages, total = await walk_all_pages(make_adapter(raw), items_per_page)
        collected = [key for page in pages for key in keys(page)]
        where = f"items_per_page={items_per_page}"

        assert len(collected) == len(set(collected)), f"{where}: a contact was served on two pages"
        assert len(collected) == total, f"{where}: pages do not add up to items_total"
        assert pages[-1], f"{where}: the last page came back empty"
        for page_items in pages[:-1]:
            assert len(page_items) == items_per_page, f"{where}: only the last page may be short"


@pytest.mark.asyncio
async def test_page_past_the_end_is_empty_and_does_not_wrap():
    raw = build_raw_accounts(30)
    adapter = make_adapter(raw)

    _, total = await fetch_page(adapter, 1, 25)
    beyond = math.ceil(total / 25) + 1
    items, total_again = await fetch_page(adapter, beyond, 25)

    assert items == []
    assert total_again == total


@pytest.mark.asyncio
async def test_requesting_user_is_never_returned():
    raw = build_raw_accounts(60)
    adapter = make_adapter(raw)

    pages, _ = await walk_all_pages(adapter, 15)

    assert str(CURRENT_I_ACCOUNT) not in [key for page in pages for key in keys(page)]


@pytest.mark.asyncio
async def test_items_per_page_1000_honours_page():
    # 1000 is the cap main.py allows; the two branches guarding it used to disagree
    # (>= when fetching, > when paginating), so every page returned the first slice.
    raw = build_raw_accounts(1500, blocked_every=0, source_every=0)
    adapter = make_adapter(raw)

    first, total = await fetch_page(adapter, 1, 1000)
    second, _ = await fetch_page(adapter, 2, 1000)

    assert total == 1500
    assert len(first) == 1000
    assert len(second) == 500
    assert not set(keys(first)) & set(keys(second))


# --- custom contacts ------------------------------------------------------

CUSTOM = [
    {"name": "Support", "number": "0800111222"},
    {"name": "Emergency", "number": "112"},
]


@pytest.mark.asyncio
async def test_custom_contacts_appear_exactly_once():
    raw = build_raw_accounts(50)

    for items_per_page in (15, 25):
        pages, total = await walk_all_pages(make_adapter(raw, custom_contacts=CUSTOM), items_per_page)
        numbers = [item.numbers.main for page in pages for item in page]

        for entry in CUSTOM:
            assert numbers.count(entry["number"]) == 1, f"items_per_page={items_per_page}"
        assert len(numbers) == total, f"items_per_page={items_per_page}"


@pytest.mark.asyncio
async def test_custom_contacts_counted_in_total():
    raw = build_raw_accounts(20)
    without = make_adapter(raw)
    with_custom = make_adapter(raw, custom_contacts=CUSTOM)

    _, total_without = await fetch_page(without, 1, 25)
    _, total_with = await fetch_page(with_custom, 1, 25)

    assert total_with == total_without + len(CUSTOM)


@pytest.mark.asyncio
async def test_custom_contacts_smaller_than_page_size():
    # target used to go <= 0 here, skipping the fetch loop entirely
    raw = build_raw_accounts(20)
    adapter = make_adapter(raw, custom_contacts=CUSTOM)

    items, total = await fetch_page(adapter, 1, 2)

    assert len(items) == 2
    assert total > len(CUSTOM)


# --- skip-without-extension raises the filtered-out fraction ---------------

@pytest.mark.asyncio
async def test_pages_stay_disjoint_with_skip_without_extension():
    raw = build_raw_accounts(80)
    for index, account in enumerate(raw):
        if index % 3 == 0:
            account["extension_id"] = ""
    adapter = make_adapter(raw, skip_without_extension=True)

    pages, total = await walk_all_pages(adapter, 15)
    collected = [key for page in pages for key in keys(page)]

    assert len(collected) == len(set(collected))
    assert len(collected) == total
    assert pages[-1]


# --- ordering / de-duplication of the chunked fetch ------------------------

@pytest.mark.asyncio
async def test_page_order_is_stable_across_requests():
    raw = build_raw_accounts(2500)
    adapter = make_adapter(raw)

    first_run, _ = await fetch_page(adapter, 2, 25)
    second_run, _ = await fetch_page(adapter, 2, 25)

    assert keys(first_run) == keys(second_run)
    assert keys(first_run) == sorted(keys(first_run), key=int)


@pytest.mark.asyncio
async def test_pages_are_disjoint_when_portabilling_row_order_is_unstable():
    # The fake serves every window in the reverse of the fixture order, so a page
    # slice taken in arrival order would differ from the ascending-i_account slice.
    # Only the explicit sort makes the boundaries land on the same rows.
    raw = build_raw_accounts(2500)
    adapter = make_adapter(raw, scramble=True)

    pages, total = await walk_all_pages(adapter, 25)
    collected = [key for page in pages for key in keys(page)]

    assert collected == sorted(collected, key=int), "page boundaries follow arrival order, not i_account"
    assert len(collected) == len(set(collected))
    assert len(collected) == total


@pytest.mark.asyncio
async def test_scrambled_chunks_still_yield_ascending_pages():
    raw = build_raw_accounts(2500)
    scrambled = make_adapter(raw, scramble=True)
    ordered = make_adapter(raw)

    from_scrambled, total_scrambled = await fetch_page(scrambled, 2, 25)
    from_ordered, total_ordered = await fetch_page(ordered, 2, 25)

    assert keys(from_scrambled) == keys(from_ordered)
    assert total_scrambled == total_ordered


# --- office hierarchy (multi-customer fan-out) ----------------------------

@pytest.mark.asyncio
async def test_hierarchy_pages_are_disjoint_and_cover_every_office():
    main = build_raw_accounts(40)
    branch_a = [make_account(7000 + n) for n in range(30)]
    branch_b = [make_account(8000 + n) for n in range(25)]
    adapter = make_adapter(main, branch_accounts={201: branch_a, 202: branch_b})

    pages, total = await walk_all_pages(adapter, 15)
    collected = [key for page in pages for key in keys(page)]

    assert len(collected) == len(set(collected))
    assert len(collected) == total
    assert pages[-1], "the last page came back empty"
    # every office is represented, and the requesting user is still excluded
    assert any(key.startswith('7') for key in collected)
    assert any(key.startswith('8') for key in collected)
    assert str(CURRENT_I_ACCOUNT) not in collected


@pytest.mark.asyncio
async def test_hierarchy_total_counts_all_offices():
    main = build_raw_accounts(10, blocked_every=0, source_every=0)
    branch = [make_account(7000 + n) for n in range(12)]
    adapter = make_adapter(main, branch_accounts={201: branch})

    _, total = await fetch_page(adapter, 1, 25)

    # 10 main accounts (the requesting user is filtered out) + 12 branch accounts
    assert total == 22


@pytest.mark.asyncio
async def test_overlapping_chunks_do_not_duplicate_contacts():
    # _get_all_accounts_by_customer issues parallel LIMIT/OFFSET queries with no
    # ORDER BY; chunk_overlap makes a later chunk re-serve the previous chunk's tail.
    raw = build_raw_accounts(2500)
    adapter = make_adapter(raw, chunk_overlap=5)

    pages, total = await walk_all_pages(adapter, 1000)
    collected = [key for page in pages for key in keys(page)]

    assert len(collected) == len(set(collected))
    assert len(collected) == total
