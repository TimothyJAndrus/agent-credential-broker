"""Multi-instance: several brokers sharing one PostgreSQL. Skipped without ACB_TEST_DATABASE_URL.

These race real connections, so they test the database guarantees, not Python locks.
"""

import os
import textwrap
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import KEYS, POLICY
from fastapi.testclient import TestClient

from acb.app import create_app
from acb.audit import PostgresAuditLog
from acb.backends.jwt_backend import JwtBackend
from acb.policy import load
from acb.store import PostgresStore

DSN = os.environ.get("ACB_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="set ACB_TEST_DATABASE_URL to a throwaway PostgreSQL")


@pytest.fixture
def cluster(tmp_path):
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS grants, nonces, audit")
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(POLICY))
    policy = load(p)
    key = JwtBackend.generate()  # instances share the signing key, as they would in production
    nodes = []
    for _ in range(3):  # three broker "instances", each with its own pool
        store = PostgresStore(DSN, max_size=8)
        nodes.append((TestClient(create_app(policy, store, PostgresAuditLog(store.pool), key)), store))
    yield nodes
    for _, s in nodes:
        s.pool.close()


def test_pickup_is_exactly_once_across_instances(cluster):
    a = {"X-Agent-Key": KEYS["reporter"]}
    h = {"X-Approver-Key": KEYS["tim"]}
    c0 = cluster[0][0]
    gids = []
    for i in range(10):
        r = c0.post(
            "/v1/grants",
            headers=a,
            json={"action": "write", "resource": f"s3://acme-data/outbox/{i}.json", "justification": "race"},
        )
        gids.append(r.json()["grant"]["id"])
        assert cluster[1][0].post(f"/v1/approvals/{gids[-1]}/approve", headers=h).status_code == 200

    barrier = threading.Barrier(30)

    def grab(args):
        node, gid = args
        barrier.wait()
        return gid, cluster[node][0].post(f"/v1/grants/{gid}/credentials", headers=a).status_code

    jobs = [(n, g) for g in gids for n in range(3)]  # every grant hit by all 3 instances at once
    with ThreadPoolExecutor(30) as ex:
        results = list(ex.map(grab, jobs))
    for gid in gids:
        codes = sorted(code for g, code in results if g == gid)
        assert codes == [200, 409, 409], (gid, codes)


def test_one_audit_chain_across_instances(cluster):
    a = {"X-Agent-Key": KEYS["reporter"]}

    def ask(i):
        node = cluster[i % 3][0]
        return node.post(
            "/v1/grants",
            headers=a,
            json={"action": "read", "resource": f"s3://acme-data/reports/{i}.csv", "justification": "load"},
        ).status_code

    with ThreadPoolExecutor(24) as ex:
        assert set(ex.map(ask, range(60))) == {201}
    audit = PostgresAuditLog(cluster[0][1].pool)
    ok, n, msg = audit.verify()
    assert ok, msg
    assert n == 120  # requested + issued for each of 60
    assert cluster[2][0].get("/healthz").json()["audit_head"] == audit.head


def test_audit_tamper_detected_in_postgres(cluster):
    import psycopg

    a = {"X-Agent-Key": KEYS["reporter"]}
    for i in range(3):
        cluster[0][0].post(
            "/v1/grants",
            headers=a,
            json={"action": "read", "resource": f"s3://acme-data/reports/{i}.csv", "justification": "x"},
        )
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("UPDATE audit SET body = jsonb_set(body, '{agent}', '\"someone-else\"') WHERE seq = 3")
    ok, n, msg = PostgresAuditLog(cluster[0][1].pool).verify()
    assert not ok and n == 3 and "changed" in msg


def test_nonce_is_single_use_across_instances(cluster):
    s1, s2 = cluster[0][1], cluster[1][1]
    assert s1.use_nonce("sigv4:abc", 600)
    assert not s2.use_nonce("sigv4:abc", 600)
