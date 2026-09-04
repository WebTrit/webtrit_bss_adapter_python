"""Account-list cache behind PortaSwitch contacts (WT-1922).

Every contacts request used to re-read the whole account list from the switch —
at the tenant of WT-1922 a median of 68 and up to 349 API calls per request —
so a burst of clients saturated the connection pool and the pod stopped being
able to open a connection at all. These tests pin the cache that removes that
load, and the field projection that keeps it affordable in memory.
"""
import asyncio
import os
import sys

import pytest

_app_path = os.path.join(os.path.dirname(__file__), '..', 'app')
sys.path.insert(0, _app_path)

# PortaSwitchSettings is instantiated at import time and its URL/credential
# fields are mandatory; supply throwaway values before importing the adapter.
os.environ.setdefault('PORTASWITCH_ADMIN_API_URL', 'https://pbx.example.com')
os.environ.setdefault('PORTASWITCH_ACCOUNT_API_URL', 'https://pbx.example.com')
os.environ.setdefault('PORTASWITCH_ADMIN_API_LOGIN', 'admin')
os.environ.setdefault('PORTASWITCH_ADMIN_API_TOKEN', 'token')
os.environ.setdefault('PORTASWITCH_SIP_SERVER_HOST', '1.2.3.4')

import bss.adapters.portaswitch.adapter as adapter_module  # noqa: E402
from bss.adapters.portaswitch.adapter import (ACCOUNT_CACHE_FIELDS,  # noqa: E402
                                              ACCOUNT_CACHE_LIST_FIELDS,
                                              ACCOUNTS_CACHE_MAX_ROWS,
                                              ACCOUNTS_CACHE_STALE_FACTOR,
                                              PortaSwitchAdapter,
                                              _project_account)
from bss.adapters.portaswitch.config import PortaSwitchSettings  # noqa: E402
from bss.adapters.portaswitch.serializer import Serializer  # noqa: E402

I_CUSTOMER = 100
CURRENT_I_ACCOUNT = 5001


def full_account(i_account=6001):
    """An account row shaped like PortaBilling's, including fields nobody reads.

    The switch returns 57 fields per account; the ones after `sip_status` here
    stand in for that ballast and must not survive the projection.
    """
    return {
        "i_account": i_account,
        "i_customer": I_CUSTOMER,
        "id": f"1000{i_account}",
        "firstname": "Ada",
        "lastname": "Lovelace",
        "companyname": "Analytical Engines",
        "email": "ada@example.com, ada@work.example.com",
        "extension_id": "101",
        "extension_name": "Ada",
        "sip_status": 1,
        "status": "active",
        "dual_version_system": None,
        "did_number": "12065550101",
        "i_master_account": None,
        "alias_list": [{"id": "12065550102", "i_account": 7, "extra": "x"}],
        "alias_did_number_list": [{"did_number": "12065550103", "junk": 1}],
        # ballast
        "balance": "3.50",
        "credit_limit": "100.00",
        "assigned_addons": [{"name": "voicemail"}],
        "service_flags": "AABBCCDD",
        "out_date_time_format": "%Y-%m-%d %H:%M:%S",
        "h323_password": "secret",
        "i_product": 42,
        "activation_date": "2020-01-01",
    }


def make_adapter(ttl):
    adapter = object.__new__(PortaSwitchAdapter)
    adapter._portaswitch_settings = PortaSwitchSettings(CONTACTS_CACHE_TTL=ttl)
    adapter._init_contacts_cache_state()
    return adapter


def counting_fetch(rows, fail=False, delay=0.0):
    """A stand-in for the real switch read, counting how often it is called."""
    calls = {"n": 0}

    async def fetch(i_customer, **search_params):
        calls["n"] += 1
        if delay:
            await asyncio.sleep(delay)
        if fail:
            raise RuntimeError("switch unavailable")
        return list(rows)

    return fetch, calls


# --- the projection ---------------------------------------------------------

def test_projection_keeps_exactly_the_documented_fields():
    projected = _project_account(full_account())
    assert set(projected) == set(ACCOUNT_CACHE_FIELDS) | set(ACCOUNT_CACHE_LIST_FIELDS)
    assert projected["alias_list"] == [{"id": "12065550102"}]
    assert projected["alias_did_number_list"] == [{"did_number": "12065550103"}]


def test_projection_preserves_the_serialized_contact():
    """The guard against silent drift: if the serializer starts reading a field
    the projection drops, the cached contact would differ from the live one."""
    account = full_account()
    assert Serializer.get_contact_info_by_account(_project_account(account), CURRENT_I_ACCOUNT) \
        == Serializer.get_contact_info_by_account(account, CURRENT_I_ACCOUNT)


def test_projection_preserves_the_fields_the_local_filter_reads():
    projected = _project_account(full_account())
    for field in ("status", "dual_version_system", "extension_id", "i_account"):
        assert field in projected, field


def test_projection_drops_absent_fields_rather_than_inventing_them():
    projected = _project_account({"i_account": 1, "id": "x", "sip_status": 0})
    assert "firstname" not in projected
    # both nested lists are always present: every consumer reads them via .get
    assert projected["alias_list"] == []
    assert projected["alias_did_number_list"] == []


# --- caching behaviour ------------------------------------------------------

@pytest.mark.asyncio
async def test_ttl_zero_disables_the_cache():
    adapter = make_adapter(0)
    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account()])
    for _ in range(3):
        await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    assert calls["n"] == 3
    assert adapter._accounts_cache == {}


@pytest.mark.asyncio
async def test_a_second_request_is_served_from_the_cache():
    adapter = make_adapter(60)
    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account()])
    first = await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    second = await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    assert calls["n"] == 1
    assert first == second
    # what is cached is the projection, not the 57-field record
    assert set(second[0]) == set(ACCOUNT_CACHE_FIELDS) | set(ACCOUNT_CACHE_LIST_FIELDS)


@pytest.mark.asyncio
async def test_search_requests_are_never_cached():
    adapter = make_adapter(60)
    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account()])
    await adapter._get_all_accounts_by_customer(I_CUSTOMER, firstname="%ada%")
    await adapter._get_all_accounts_by_customer(I_CUSTOMER, firstname="%ada%")
    assert calls["n"] == 2
    assert adapter._accounts_cache == {}


@pytest.mark.asyncio
async def test_a_burst_of_requests_costs_one_read():
    """The single-flight: this is the property that keeps a burst of clients from
    each starting its own full read of the account list."""
    adapter = make_adapter(60)
    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account()], delay=0.05)
    results = await asyncio.gather(
        *(adapter._get_all_accounts_by_customer(I_CUSTOMER) for _ in range(20))
    )
    assert calls["n"] == 1
    assert all(result == results[0] for result in results)


@pytest.mark.asyncio
async def test_a_stale_entry_is_served_at_once_and_refreshed_behind_the_request():
    adapter = make_adapter(1)
    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account(6001)])
    await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    assert calls["n"] == 1

    # age the entry past the TTL but well inside the stale window
    stored_at, cached = adapter._accounts_cache[I_CUSTOMER]
    adapter._accounts_cache[I_CUSTOMER] = (stored_at - 2, cached)

    adapter._fetch_accounts_by_customer, refresh_calls = counting_fetch([full_account(6002)])
    served = await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    # served without waiting: still the old row, and the read has not happened yet
    assert served[0]["i_account"] == 6001
    assert refresh_calls["n"] == 0

    await asyncio.gather(*adapter._accounts_refresh_tasks.values())
    assert refresh_calls["n"] == 1
    assert adapter._accounts_cache[I_CUSTOMER][1][0]["i_account"] == 6002


@pytest.mark.asyncio
async def test_an_entry_past_the_stale_window_is_re_read_before_answering():
    adapter = make_adapter(1)
    adapter._fetch_accounts_by_customer, _ = counting_fetch([full_account(6001)])
    await adapter._get_all_accounts_by_customer(I_CUSTOMER)

    stored_at, cached = adapter._accounts_cache[I_CUSTOMER]
    adapter._accounts_cache[I_CUSTOMER] = (
        stored_at - ACCOUNTS_CACHE_STALE_FACTOR - 1, cached
    )

    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account(6002)])
    served = await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    assert calls["n"] == 1
    assert served[0]["i_account"] == 6002


@pytest.mark.asyncio
async def test_a_failed_refresh_keeps_serving_the_previous_list():
    """A switch hiccup must not turn a list we could still serve into an error."""
    adapter = make_adapter(1)
    adapter._fetch_accounts_by_customer, _ = counting_fetch([full_account(6001)])
    await adapter._get_all_accounts_by_customer(I_CUSTOMER)

    stored_at, cached = adapter._accounts_cache[I_CUSTOMER]
    adapter._accounts_cache[I_CUSTOMER] = (stored_at - 2, cached)

    adapter._fetch_accounts_by_customer, _ = counting_fetch([], fail=True)
    await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    await asyncio.gather(*adapter._accounts_refresh_tasks.values())

    assert adapter._accounts_cache[I_CUSTOMER][1][0]["i_account"] == 6001
    served = await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    assert served[0]["i_account"] == 6001


@pytest.mark.asyncio
async def test_the_row_budget_evicts_the_oldest_customer():
    adapter = make_adapter(600)
    per_customer = ACCOUNTS_CACHE_MAX_ROWS // 2 + 1
    rows = [full_account(6000 + n) for n in range(per_customer)]
    adapter._fetch_accounts_by_customer, _ = counting_fetch(rows)

    await adapter._get_all_accounts_by_customer(1)
    await adapter._get_all_accounts_by_customer(2)

    assert 1 not in adapter._accounts_cache, "the oldest entry should have been evicted"
    assert 2 in adapter._accounts_cache, "the entry just stored must survive"


@pytest.mark.asyncio
async def test_a_single_customer_larger_than_the_budget_is_still_served():
    adapter = make_adapter(600)
    rows = [full_account(6000 + n) for n in range(ACCOUNTS_CACHE_MAX_ROWS + 1)]
    adapter._fetch_accounts_by_customer, calls = counting_fetch(rows)

    await adapter._get_all_accounts_by_customer(1)
    await adapter._get_all_accounts_by_customer(1)

    assert calls["n"] == 1, "re-reading it every time is what the cache exists to avoid"


# --- what the counters say --------------------------------------------------

@pytest.fixture
def recorded(monkeypatch):
    """Collect the cache events the adapter records."""
    events = []
    monkeypatch.setattr(adapter_module, "_record_cache_event", events.append)
    return events


@pytest.mark.asyncio
async def test_a_coalesced_burst_reports_one_miss(recorded):
    """`miss` has to mean "waited on a read of the switch". Recording it per
    request made a burst that cost one read look like a 100% miss rate, which
    reads as a cache that is not working."""
    adapter = make_adapter(60)
    adapter._fetch_accounts_by_customer, calls = counting_fetch([full_account()], delay=0.05)
    await asyncio.gather(
        *(adapter._get_all_accounts_by_customer(I_CUSTOMER) for _ in range(20))
    )
    assert calls["n"] == 1
    assert recorded.count("miss") == 1
    assert recorded.count("coalesced") == 19
    assert recorded.count("hit") == 0


@pytest.mark.asyncio
async def test_requests_after_the_read_report_hits(recorded):
    adapter = make_adapter(60)
    adapter._fetch_accounts_by_customer, _ = counting_fetch([full_account()])
    for _ in range(3):
        await adapter._get_all_accounts_by_customer(I_CUSTOMER)
    assert recorded == ["miss", "hit", "hit"]


# --- background refresh bookkeeping ----------------------------------------

@pytest.mark.asyncio
async def test_a_finished_task_does_not_delete_its_replacement():
    """A done-callback runs via call_soon, so a replacement can be scheduled
    first; popping blindly would delete it and drop the only strong reference
    the loop does not hold."""
    adapter = make_adapter(1)
    adapter._fetch_accounts_by_customer, _ = counting_fetch([full_account()])

    async def noop():
        return None

    finished = asyncio.get_running_loop().create_task(noop())
    await finished
    adapter._accounts_refresh_tasks[I_CUSTOMER] = finished

    replacement = asyncio.get_running_loop().create_task(noop())
    adapter._accounts_refresh_tasks[I_CUSTOMER] = replacement
    adapter._forget_refresh_task(I_CUSTOMER, finished)

    assert adapter._accounts_refresh_tasks.get(I_CUSTOMER) is replacement
    await replacement
    adapter._forget_refresh_task(I_CUSTOMER, replacement)
    assert I_CUSTOMER not in adapter._accounts_refresh_tasks


@pytest.mark.asyncio
async def test_an_empty_entry_does_not_cost_every_other_customer():
    """Evicting an entry that frees nothing would walk the whole cache away."""
    adapter = make_adapter(600)
    rows = [full_account(6000 + n) for n in range(ACCOUNTS_CACHE_MAX_ROWS + 1)]
    adapter._accounts_cache[7] = (0.0, [])
    adapter._accounts_cache[8] = (1.0, [])
    adapter._fetch_accounts_by_customer, _ = counting_fetch(rows)

    await adapter._get_all_accounts_by_customer(9)

    assert 7 in adapter._accounts_cache and 8 in adapter._accounts_cache
    assert 9 in adapter._accounts_cache


@pytest.mark.asyncio
async def test_eviction_drops_the_lock_it_no_longer_guards():
    adapter = make_adapter(600)
    per_customer = ACCOUNTS_CACHE_MAX_ROWS // 2 + 1
    rows = [full_account(6000 + n) for n in range(per_customer)]
    adapter._fetch_accounts_by_customer, _ = counting_fetch(rows)

    await adapter._get_all_accounts_by_customer(1)
    await adapter._get_all_accounts_by_customer(2)

    assert 1 not in adapter._accounts_cache
    assert 1 not in adapter._accounts_cache_locks, "the lock outlived its entry"
