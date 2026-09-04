"""Call center "My Queues" support in PortaSwitchAdapter (WT-1881).

Covers the two things the PortaSwitch API forced on the design and that are easy to
regress:

* the queue list must be built from the ADMIN realm - the account realm returns only
  the caller's own membership row, stripped of account_id/id/name - and must be filtered
  down to hunt groups that really carry a call queue and really include this agent;
* `callers_waiting` is optional. `None` means "unknown" (live counters off, or Call
  Control unreachable) and must never be flattened into 0, because a queue with nobody
  waiting is a genuine 0.
"""
import asyncio
import os
import sys

import pytest

_app_path = os.path.join(os.path.dirname(__file__), '..', 'app')
sys.path.insert(0, _app_path)

# PortaSwitchSettings is instantiated at import time and its URL/credential fields are
# mandatory; supply throwaway values before importing the adapter.
os.environ.setdefault('PORTASWITCH_ADMIN_API_URL', 'https://pbx.example.com')
os.environ.setdefault('PORTASWITCH_ACCOUNT_API_URL', 'https://pbx.example.com')
os.environ.setdefault('PORTASWITCH_ADMIN_API_LOGIN', 'admin')
os.environ.setdefault('PORTASWITCH_ADMIN_API_TOKEN', 'token')
os.environ.setdefault('PORTASWITCH_SIP_SERVER_HOST', '1.2.3.4')

from bss.adapters.portaswitch.adapter import (
    CALL_CONTROL_NOT_SUBSCRIBED_FAULT,
    CALL_QUEUE_COUNTERS_CACHE_MAX,
    HUNTGROUP_MAX_PAGES,
    HUNTGROUP_PAGE_LIMIT,
    PortaSwitchAdapter,
)
from bss.adapters.portaswitch.config import PortaSwitchSettings
from bss.adapters.portaswitch.serializer import Serializer
from bss.types import SessionInfo, UserInfo
from report_error import WebTritErrorException

I_CUSTOMER = 8045
I_ACCOUNT = 102398
AGENT_ID = "111000111"
OTHER_AGENT_ID = "111000888"


def fault(code):
    """A WebTritErrorException shaped the way extract_fault_code expects."""
    return WebTritErrorException(
        500, "boom",
        bss_response_trace={"response_content": {"faultcode": code}},
    )


def _failing_enable(admin):
    """enable_api_notifications that reports success without actually subscribing."""
    async def enable(i_customer):
        admin.enable_calls.append(i_customer)
        return {"success": 1}
    return enable


def member(account_id, hunt_active="Y", ext_type="Account", name=None):
    return {
        "account_id": account_id,
        "id": account_id[-3:] if account_id else None,
        "name": name,
        "type": ext_type,
        "hunt_active": hunt_active,
    }


def huntgroup(hg_id, members, i_c_queue=364, name=None):
    hg = {
        "i_c_group": 1000 + int(hg_id) if hg_id.isdigit() else 1000,
        "id": hg_id,
        "name": name,
        "activity_monitoring": "N",
        "assigned_extensions": members,
    }
    if i_c_queue is not None:
        hg["assigned_callqueue"] = {"i_c_queue": i_c_queue, "incoming_capacity": 10}
    return hg


# --------------------------------------------------------------------------- #
# Serializer
# --------------------------------------------------------------------------- #

class TestIsCallQueue:
    def test_group_with_queue(self):
        assert Serializer.is_call_queue(huntgroup("340", [])) is True

    def test_group_without_callqueue_key(self):
        assert Serializer.is_call_queue(huntgroup("340", [], i_c_queue=None)) is False

    def test_empty_callqueue_object_is_not_a_queue(self):
        # CQInfo declares no required fields, so {} is schema-valid and must not
        # be mistaken for a configured queue.
        hg = huntgroup("340", [], i_c_queue=None)
        hg["assigned_callqueue"] = {}
        assert Serializer.is_call_queue(hg) is False

    def test_null_callqueue(self):
        hg = huntgroup("340", [], i_c_queue=None)
        hg["assigned_callqueue"] = None
        assert Serializer.is_call_queue(hg) is False


class TestMembership:
    def test_agent_is_member(self):
        hg = huntgroup("340", [member(AGENT_ID), member(OTHER_AGENT_ID)])
        assert Serializer.is_huntgroup_member(hg, AGENT_ID) is True

    def test_agent_is_not_member(self):
        hg = huntgroup("340", [member(OTHER_AGENT_ID)])
        assert Serializer.is_huntgroup_member(hg, AGENT_ID) is False

    def test_non_account_extensions_are_not_agents(self):
        # Real demo data carries Group / Unassigned rows with account_id = None.
        hg = huntgroup("340", [
            member(None, ext_type="Group"),
            member(None, ext_type="Unassigned"),
            member(AGENT_ID),
        ])
        assert Serializer._huntgroup_account_members(hg) == [member(AGENT_ID)]

    def test_logged_out_agent_is_still_a_member(self):
        hg = huntgroup("340", [member(AGENT_ID, hunt_active="N")])
        assert Serializer.is_huntgroup_member(hg, AGENT_ID) is True


class TestCountCallersWaiting:
    def test_counts_queued_calls_per_huntgroup(self):
        calls = [
            {"state": "queued", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
            {"state": "queued", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
            {"state": "queued", "queue_info": {"i_c_queue": 2}, "callee": {"huntgroup_id": "350"}},
        ]
        assert Serializer.count_callers_waiting(calls) == {"340": 2, "350": 1}

    def test_connected_calls_are_not_waiting(self):
        calls = [
            {"state": "connected", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
            {"state": "ringing", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
        ]
        assert Serializer.count_callers_waiting(calls) == {}

    def test_queued_call_without_queue_info_is_ignored(self):
        calls = [{"state": "queued", "callee": {"huntgroup_id": "340"}}]
        assert Serializer.count_callers_waiting(calls) == {}

    def test_call_without_huntgroup_is_ignored(self):
        calls = [{"state": "queued", "queue_info": {"i_c_queue": 1}, "callee": {}}]
        assert Serializer.count_callers_waiting(calls) == {}

    def test_empty_input(self):
        assert Serializer.count_callers_waiting([]) == {}
        assert Serializer.count_callers_waiting(None) == {}


class TestGetCallQueue:
    def test_logged_in_agent(self):
        hg = huntgroup("340", [member(AGENT_ID, "Y"), member(OTHER_AGENT_ID, "N")], name="Support")
        queue = Serializer.get_call_queue(hg, AGENT_ID, callers_waiting=3)

        assert queue.id == "340"
        assert queue.name == "Support"
        assert queue.logged_in is True
        assert queue.agents_total == 2
        assert queue.agents_logged_in == 1
        assert queue.callers_waiting == 3

    def test_logged_out_agent(self):
        hg = huntgroup("340", [member(AGENT_ID, "N"), member(OTHER_AGENT_ID, "Y")])
        queue = Serializer.get_call_queue(hg, AGENT_ID)

        assert queue.logged_in is False
        assert queue.agents_logged_in == 1
        # Unknown, not zero.
        assert queue.callers_waiting is None

    def test_zero_waiting_is_kept_distinct_from_unknown(self):
        hg = huntgroup("340", [member(AGENT_ID)])
        assert Serializer.get_call_queue(hg, AGENT_ID, callers_waiting=0).callers_waiting == 0

    def test_name_falls_back_to_the_group_number(self):
        hg = huntgroup("340", [member(AGENT_ID)], name=None)
        assert Serializer.get_call_queue(hg, AGENT_ID).name == "340"

    def test_agent_missing_from_members(self):
        hg = huntgroup("340", [member(OTHER_AGENT_ID, "Y")])
        queue = Serializer.get_call_queue(hg, AGENT_ID)
        assert queue.logged_in is False
        assert queue.agents_logged_in == 1

    def test_group_extensions_are_excluded_from_the_agent_count(self):
        hg = huntgroup("340", [member(AGENT_ID, "Y"), member(None, "Y", ext_type="Group")])
        queue = Serializer.get_call_queue(hg, AGENT_ID)
        assert queue.agents_total == 1
        assert queue.agents_logged_in == 1


# --------------------------------------------------------------------------- #
# Adapter
# --------------------------------------------------------------------------- #

class FakeAccountAPI:
    def __init__(self):
        self.info = {"i_account": I_ACCOUNT, "i_customer": I_CUSTOMER, "id": AGENT_ID}

    async def get_account_info(self, access_token):
        return {"account_info": self.info}


class FakeAdminAPI:
    def __init__(self, huntgroups, calls=None, calls_fault=None, subscribed=True):
        self.huntgroups = huntgroups
        self.expected_customer = I_CUSTOMER
        self.calls = calls or []
        self.calls_fault = calls_fault
        self.subscribed = subscribed
        self.subscription_calls = []
        self.enable_calls = []
        self.sip_calls_requests = 0
        self.huntgroup_list_requests = 0

    #: PortaBilling list methods cap the result server-side when no limit is given;
    #: emulating that is what makes the paging tests meaningful.
    SERVER_DEFAULT_CAP = 100

    async def get_huntgroup_list(self, i_customer, limit=None, offset=None):
        self.huntgroup_list_requests += 1
        assert i_customer == self.expected_customer
        assert limit is not None or not offset, "PortaBilling requires limit when offset is set"
        page = self.huntgroups[(offset or 0):]
        page = page[:limit if limit is not None else self.SERVER_DEFAULT_CAP]
        return {"huntgroup_list": page, "total": len(self.huntgroups)}

    async def get_sip_calls_list(self, i_customer):
        # Yield to the event loop so concurrent callers really do overlap; without a
        # suspension point gather() would run each coroutine to completion in turn and
        # the single-flight test would pass even with no lock at all.
        await asyncio.sleep(0)
        self.sip_calls_requests += 1
        if self.calls_fault:
            raise self.calls_fault
        if not self.subscribed:
            raise fault(CALL_CONTROL_NOT_SUBSCRIBED_FAULT)
        return {"calls_list": self.calls}

    async def enable_api_notifications(self, i_customer):
        self.enable_calls.append(i_customer)
        self.subscribed = True
        return {"success": 1}

    async def update_huntgroups_subscription(self, i_account, subscribe=None, unsubscribe=None):
        self.subscription_calls.append(
            {"i_account": i_account, "subscribe": subscribe, "unsubscribe": unsubscribe}
        )
        for hg in self.huntgroups:
            for ext in hg.get("assigned_extensions") or []:
                if ext.get("account_id") != AGENT_ID:
                    continue
                if unsubscribe and hg["id"] in unsubscribe:
                    ext["hunt_active"] = "N"
                elif subscribe and hg["id"] in subscribe:
                    ext["hunt_active"] = "Y"
        return {"success": 1}


def make_adapter(huntgroups, calls=None, calls_fault=None, subscribed=True):
    settings = PortaSwitchSettings(
        ADMIN_API_URL='https://pbx.example.com',
        ACCOUNT_API_URL='https://pbx.example.com',
        ADMIN_API_LOGIN='admin',
        ADMIN_API_TOKEN='token',
        SIP_SERVER_HOST='1.2.3.4',
    )
    # Bypass __init__: it builds HTTP connectors, OTP storage and failover state,
    # none of which the call center path touches.
    adapter = object.__new__(PortaSwitchAdapter)
    adapter._portaswitch_settings = settings
    adapter._admin_api = FakeAdminAPI(huntgroups, calls=calls, calls_fault=calls_fault,
                                      subscribed=subscribed)
    adapter._account_api = FakeAccountAPI()
    # Go through the real initialiser so deleting it from __init__ breaks these tests.
    adapter._init_call_queue_state()
    return adapter


SESSION = SessionInfo(user_id=str(I_ACCOUNT), access_token="tok")
USER = UserInfo(user_id=str(I_ACCOUNT))


def mixed_huntgroups():
    """A realistic customer: two queues the agent serves, one queue they do not,
    and one plain hunt group that has no queue at all."""
    return [
        huntgroup("340", [member(AGENT_ID, "Y"), member(OTHER_AGENT_ID, "N")], name="Support"),
        huntgroup("350", [member(AGENT_ID, "N")], name="Sales"),
        huntgroup("501", [member(OTHER_AGENT_ID, "Y")], name="Not mine"),
        huntgroup("0111", [member(AGENT_ID, "Y")], i_c_queue=None, name="Plain hunt group"),
    ]


class TestRetrieveCallQueues:
    @pytest.mark.asyncio
    async def test_only_queues_the_agent_belongs_to(self):
        adapter = make_adapter(mixed_huntgroups())
        result = await adapter.retrieve_call_queues(SESSION, USER)

        assert [q.id for q in result.items] == ["340", "350"]
        assert [q.logged_in for q in result.items] == [True, False]

    @pytest.mark.asyncio
    async def test_non_agent_gets_an_empty_list(self):
        adapter = make_adapter([huntgroup("501", [member(OTHER_AGENT_ID)])])
        result = await adapter.retrieve_call_queues(SESSION, USER)
        assert result.items == []

    @pytest.mark.asyncio
    async def test_counters_reported_when_enabled(self):
        calls = [
            {"state": "queued", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
            {"state": "queued", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
        ]
        adapter = make_adapter(mixed_huntgroups(), calls=calls)
        result = await adapter.retrieve_call_queues(SESSION, USER)

        by_id = {q.id: q for q in result.items}
        assert by_id["340"].callers_waiting == 2
        # Answered by the switch, nobody queued - a real zero, not unknown.
        assert by_id["350"].callers_waiting == 0

    @pytest.mark.asyncio
    async def test_subscription_is_created_on_demand(self):
        adapter = make_adapter(mixed_huntgroups(), subscribed=False,
                               calls=[{"state": "queued", "queue_info": {"i_c_queue": 1},
                                       "callee": {"huntgroup_id": "340"}}])
        result = await adapter.retrieve_call_queues(SESSION, USER)

        assert adapter._admin_api.enable_calls == [I_CUSTOMER]
        assert adapter._admin_api.sip_calls_requests == 2
        # PortaSIP only tracks call state from the moment of subscription, so the read
        # that created it cannot be trusted to have seen already-queued callers.
        assert all(q.callers_waiting is None for q in result.items)

    @pytest.mark.asyncio
    async def test_counters_are_trusted_once_the_subscription_exists(self):
        adapter = make_adapter(mixed_huntgroups(), subscribed=False,
                               calls=[{"state": "queued", "queue_info": {"i_c_queue": 1},
                                       "callee": {"huntgroup_id": "340"}}])
        await adapter.retrieve_call_queues(SESSION, USER)
        # Stand in for the TTL expiring between two polls.
        adapter._call_queue_counters_cache.clear()
        result = await adapter.retrieve_call_queues(SESSION, USER)

        assert adapter._admin_api.enable_calls == [I_CUSTOMER]
        assert {q.id: q.callers_waiting for q in result.items} == {"340": 1, "350": 0}

    @pytest.mark.asyncio
    async def test_subscription_that_keeps_failing_is_not_retried_in_a_loop(self):
        adapter = make_adapter(mixed_huntgroups(), subscribed=False)
        # enable_api_notifications "succeeds" but the scope stays unsubscribed.
        adapter._admin_api.enable_api_notifications = _failing_enable(adapter._admin_api)

        result = await adapter.retrieve_call_queues(SESSION, USER)

        assert all(q.callers_waiting is None for q in result.items)
        # One read, one enable, one retry - then it gives up.
        assert adapter._admin_api.sip_calls_requests == 2

    @pytest.mark.asyncio
    async def test_call_control_failure_degrades_to_unknown(self):
        adapter = make_adapter(mixed_huntgroups(), calls_fault=fault("Server.CallControl.get_sip_calls_list.access_denied"))
        result = await adapter.retrieve_call_queues(SESSION, USER)

        # The queue list still works; only the counters are missing.
        assert [q.id for q in result.items] == ["340", "350"]
        assert all(q.callers_waiting is None for q in result.items)

    @pytest.mark.asyncio
    async def test_counters_are_cached_within_the_ttl(self):
        adapter = make_adapter(mixed_huntgroups(), calls=[])
        await adapter.retrieve_call_queues(SESSION, USER)
        await adapter.retrieve_call_queues(SESSION, USER)

        assert adapter._admin_api.sip_calls_requests == 1

    @pytest.mark.asyncio
    async def test_expired_token_is_reported_as_such(self):
        adapter = make_adapter(mixed_huntgroups())

        async def boom(access_token):
            raise fault("Client.Session.check_auth.failed_to_process_access_token")

        adapter._account_api.get_account_info = boom

        with pytest.raises(WebTritErrorException) as exc:
            await adapter.retrieve_call_queues(SESSION, USER)
        assert exc.value.status_code == 401


class TestHuntgroupPaging:
    @pytest.mark.asyncio
    async def test_queues_past_the_first_page_are_still_found(self):
        # A customer with more hunt groups than one page: without paging the agent's
        # queue would vanish from the list and log in / log out would 404 on it.
        filler = [huntgroup(str(4000 + n), [member(OTHER_AGENT_ID)]) for n in range(HUNTGROUP_PAGE_LIMIT)]
        mine = huntgroup("340", [member(AGENT_ID, "Y")], name="Support")
        adapter = make_adapter(filler + [mine])

        result = await adapter.retrieve_call_queues(SESSION, USER)

        assert [q.id for q in result.items] == ["340"]
        assert adapter._admin_api.huntgroup_list_requests == 2

    @pytest.mark.asyncio
    async def test_a_single_page_costs_one_request(self):
        adapter = make_adapter(mixed_huntgroups())
        await adapter.retrieve_call_queues(SESSION, USER)

        assert adapter._admin_api.huntgroup_list_requests == 1

    @pytest.mark.asyncio
    async def test_paging_is_bounded(self):
        # A switch that keeps returning full pages must not spin forever.
        class Endless(FakeAdminAPI):
            async def get_huntgroup_list(self, i_customer, limit=None, offset=None):
                self.huntgroup_list_requests += 1
                return {"huntgroup_list": [huntgroup(str(9000 + n), [member(OTHER_AGENT_ID)])
                                           for n in range(limit)]}

        adapter = make_adapter(mixed_huntgroups())
        adapter._admin_api = Endless(mixed_huntgroups())

        result = await adapter.retrieve_call_queues(SESSION, USER)

        assert result.items == []
        assert adapter._admin_api.huntgroup_list_requests == HUNTGROUP_MAX_PAGES


class TestCountersCache:
    @pytest.mark.asyncio
    async def test_failed_lookups_are_cached_too(self):
        adapter = make_adapter(mixed_huntgroups(),
                               calls_fault=fault("Server.CallControl.get_sip_calls_list.access_denied"))
        await adapter.retrieve_call_queues(SESSION, USER)
        await adapter.retrieve_call_queues(SESSION, USER)

        # Without negative caching every poll on an installation without Call Control
        # access would cost a failing request and a warning.
        assert adapter._admin_api.sip_calls_requests == 1

    @pytest.mark.asyncio
    async def test_customers_do_not_share_counters(self):
        adapter = make_adapter(mixed_huntgroups(), calls=[
            {"state": "queued", "queue_info": {"i_c_queue": 1}, "callee": {"huntgroup_id": "340"}},
        ])
        await adapter.retrieve_call_queues(SESSION, USER)

        other_customer = I_CUSTOMER + 1
        adapter._account_api.info = {"i_account": 999, "i_customer": other_customer, "id": AGENT_ID}
        adapter._admin_api.expected_customer = other_customer
        adapter._admin_api.calls = []
        await adapter.retrieve_call_queues(SESSION, USER)

        # A second customer must not be served the first one's cached numbers.
        assert adapter._admin_api.sip_calls_requests == 2
        assert set(adapter._call_queue_counters_cache) == {I_CUSTOMER, other_customer}

    @pytest.mark.asyncio
    async def test_a_burst_of_polls_costs_one_switch_request(self):
        adapter = make_adapter(mixed_huntgroups(), calls=[])
        await asyncio.gather(*(adapter.retrieve_call_queues(SESSION, USER) for _ in range(10)))

        assert adapter._admin_api.sip_calls_requests == 1

    @pytest.mark.asyncio
    async def test_cache_is_bounded(self):
        adapter = make_adapter(mixed_huntgroups(), calls=[])
        for n in range(CALL_QUEUE_COUNTERS_CACHE_MAX + 25):
            adapter._store_callers_waiting(n, {})

        assert len(adapter._call_queue_counters_cache) == CALL_QUEUE_COUNTERS_CACHE_MAX


class TestSetCallQueueLogin:
    @pytest.mark.asyncio
    async def test_logout_of_one_queue(self):
        adapter = make_adapter(mixed_huntgroups())
        queue = await adapter.set_call_queue_login(SESSION, USER, "340", logged_in=False)

        assert adapter._admin_api.subscription_calls == [
            {"i_account": I_ACCOUNT, "subscribe": None, "unsubscribe": ["340"]}
        ]
        assert queue.id == "340"
        assert queue.logged_in is False
        # The other agent in that queue is untouched.
        assert queue.agents_logged_in == 0

    @pytest.mark.asyncio
    async def test_login_to_one_queue(self):
        adapter = make_adapter(mixed_huntgroups())
        queue = await adapter.set_call_queue_login(SESSION, USER, "350", logged_in=True)

        assert adapter._admin_api.subscription_calls == [
            {"i_account": I_ACCOUNT, "subscribe": ["350"], "unsubscribe": None}
        ]
        assert queue.logged_in is True

    @pytest.mark.asyncio
    async def test_queue_the_agent_does_not_serve_is_rejected(self):
        adapter = make_adapter(mixed_huntgroups())

        with pytest.raises(WebTritErrorException) as exc:
            await adapter.set_call_queue_login(SESSION, USER, "501", logged_in=False)

        assert exc.value.status_code == 404
        # Nothing was sent to the switch - the admin session could have changed it.
        assert adapter._admin_api.subscription_calls == []

    @pytest.mark.asyncio
    async def test_plain_hunt_group_is_rejected(self):
        adapter = make_adapter(mixed_huntgroups())

        with pytest.raises(WebTritErrorException) as exc:
            await adapter.set_call_queue_login(SESSION, USER, "0111", logged_in=False)

        assert exc.value.status_code == 404
        assert adapter._admin_api.subscription_calls == []


    @pytest.mark.asyncio
    async def test_queue_disappearing_after_the_update_is_reported_as_404(self):
        adapter = make_adapter(mixed_huntgroups())
        admin = adapter._admin_api
        original = admin.update_huntgroups_subscription

        async def drop_the_queue(i_account, subscribe=None, unsubscribe=None):
            result = await original(i_account, subscribe=subscribe, unsubscribe=unsubscribe)
            admin.huntgroups = [hg for hg in admin.huntgroups if hg["id"] != "340"]
            return result

        admin.update_huntgroups_subscription = drop_the_queue

        # A bare next() here would raise StopIteration, which asyncio re-raises as an
        # opaque RuntimeError that no handler recognises.
        with pytest.raises(WebTritErrorException) as exc:
            await adapter.set_call_queue_login(SESSION, USER, "340", logged_in=False)
        assert exc.value.status_code == 404


class TestSetAllCallQueuesLogin:
    @pytest.mark.asyncio
    async def test_logout_of_all_queues_is_one_request(self):
        adapter = make_adapter(mixed_huntgroups())
        result = await adapter.set_all_call_queues_login(SESSION, USER, logged_in=False)

        assert adapter._admin_api.subscription_calls == [
            {"i_account": I_ACCOUNT, "subscribe": None, "unsubscribe": ["340", "350"]}
        ]
        assert [q.logged_in for q in result.items] == [False, False]

    @pytest.mark.asyncio
    async def test_login_to_all_queues(self):
        adapter = make_adapter(mixed_huntgroups())
        result = await adapter.set_all_call_queues_login(SESSION, USER, logged_in=True)

        assert adapter._admin_api.subscription_calls == [
            {"i_account": I_ACCOUNT, "subscribe": ["340", "350"], "unsubscribe": None}
        ]
        assert [q.logged_in for q in result.items] == [True, True]

    @pytest.mark.asyncio
    async def test_no_queues_means_no_switch_call(self):
        adapter = make_adapter([huntgroup("501", [member(OTHER_AGENT_ID)])])
        result = await adapter.set_all_call_queues_login(SESSION, USER, logged_in=False)

        assert result.items == []
        assert adapter._admin_api.subscription_calls == []
