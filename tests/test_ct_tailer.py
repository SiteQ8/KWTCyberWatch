#!/usr/bin/env python3
"""Tests for the dependency-free X.509 parser and the direct CT log tailer."""

import base64
import struct
from datetime import datetime, timezone

import pytest

from src.config.settings import CertStreamConfig
from src.core.certstream_monitor import CertStreamMonitor
from src.core.ct_tailer import FALLBACK_LOGS, CTLogTailer, select_logs_from_list
from src.utils import x509

# --------------------------------------------------------------------------- #
# Tiny DER encoder used to build test certificates without any dependency
# --------------------------------------------------------------------------- #


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def name(cn: str = "", org: str = "") -> bytes:
    rdns = b""
    if org:
        rdns += tlv(0x31, seq(tlv(0x06, x509.OID_O), tlv(0x0C, org.encode())))
    if cn:
        rdns += tlv(0x31, seq(tlv(0x06, x509.OID_CN), tlv(0x0C, cn.encode())))
    return seq(rdns) if rdns else seq()


def utc_time(text: str) -> bytes:
    return tlv(0x17, text.encode())


def san(*dns: str) -> bytes:
    general_names = b"".join(tlv(0x82, d.encode()) for d in dns)
    return seq(tlv(0x06, x509.OID_SAN), tlv(0x04, seq(general_names)))


def tbs(
    cn: str,
    dns,
    issuer_org="Let's Encrypt",
    poison=False,
    not_before="250101000000Z",
    not_after="260101000000Z",
) -> bytes:
    exts = san(*dns)
    if poison:
        exts += seq(tlv(0x06, x509.OID_CT_POISON), tlv(0x01, b"\xff"), tlv(0x04, b"\x05\x00"))
    return seq(
        tlv(0xA0, tlv(0x02, b"\x02")),  # version v3
        tlv(0x02, b"\x01\x02\x03"),  # serial
        seq(tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")),  # sha256WithRSA
        name(cn="R11", org=issuer_org),
        seq(utc_time(not_before), utc_time(not_after)),
        name(cn=cn),
        seq(
            seq(tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"), tlv(0x05, b"")),
            tlv(0x03, b"\x00\x00"),
        ),
        tlv(0xA3, seq(exts)),
    )


def certificate(cn: str, dns, **kw) -> bytes:
    return seq(
        tbs(cn, dns, **kw),
        seq(tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")),
        tlv(0x03, b"\x00\xaa"),
    )


def leaf_input(der: bytes, entry_type: int, timestamp_ms: int = 1_700_000_000_000) -> str:
    body = bytes([0, 0]) + struct.pack(">Q", timestamp_ms) + struct.pack(">H", entry_type)
    if entry_type == 0:
        body += len(der).to_bytes(3, "big") + der
    else:
        body += b"\x11" * 32 + len(der).to_bytes(3, "big") + der
    body += b"\x00\x00"
    return base64.b64encode(body).decode()


# --------------------------------------------------------------------------- #


class TestX509:
    def test_parse_full_certificate(self):
        der = certificate("login.nbk-secure.xyz", ["login.nbk-secure.xyz", "www.nbk-secure.xyz"])
        parsed = x509.parse_certificate(der)
        assert parsed["all_domains"] == ["login.nbk-secure.xyz", "www.nbk-secure.xyz"]
        assert parsed["issuer"] == {"O": "Let's Encrypt", "CN": "R11"}
        assert parsed["subject"]["CN"] == "login.nbk-secure.xyz"
        assert parsed["serial_number"] == "010203"
        assert parsed["not_before"].startswith("2025-01-01T00:00:00")
        assert parsed["not_after"].startswith("2026-01-01T00:00:00")
        assert parsed["is_precert"] is False

    def test_parse_bare_tbs_and_poison(self):
        parsed = x509.parse_certificate(tbs("kfh-verify.top", ["kfh-verify.top"], poison=True))
        assert parsed["all_domains"] == ["kfh-verify.top"]
        assert parsed["is_precert"] is True

    def test_cn_without_san_and_dedupe(self):
        parsed = x509.parse_certificate(certificate("a.example", ["a.example", "A.EXAMPLE"]))
        assert parsed["all_domains"] == ["a.example"]

    def test_long_form_length(self):
        many = [f"host{i}.kuwait-example.com" for i in range(40)]
        parsed = x509.parse_certificate(certificate("host0.kuwait-example.com", many))
        assert len(parsed["all_domains"]) == 40

    def test_leaf_input_x509_and_precert(self):
        der = certificate("zain-kw-login.top", ["zain-kw-login.top"])
        x = x509.parse_leaf_input(leaf_input(der, 0))
        assert x["entry_type"] == "x509" and x["timestamp"] == 1_700_000_000_000
        p = x509.parse_leaf_input(leaf_input(tbs("zain-kw-login.top", ["zain-kw-login.top"]), 1))
        assert p["entry_type"] == "precert" and p["all_domains"] == ["zain-kw-login.top"]

    def test_bad_input_raises(self):
        with pytest.raises(x509.DERError):
            x509.parse_certificate(b"\x02\x01\x01")
        with pytest.raises(x509.DERError):
            x509.parse_leaf_input(base64.b64encode(b"\x00\x00").decode())
        with pytest.raises(x509.DERError):
            x509.read_tlv(b"\x30\x85", 0)

    def test_certstream_message_shape(self):
        parsed = x509.parse_certificate(certificate("moi-kw.com", ["moi-kw.com"]))
        parsed["entry_type"] = "x509"
        parsed["timestamp"] = 1000
        msg = x509.to_certstream_message(parsed, "Test log", 7)
        assert msg["message_type"] == "certificate_update"
        assert msg["data"]["leaf_cert"]["all_domains"] == ["moi-kw.com"]
        assert msg["data"]["source"]["name"] == "Test log" and msg["data"]["cert_index"] == 7


# --------------------------------------------------------------------------- #


class FakeLog:
    """In-memory RFC 6962 log."""

    def __init__(self, entries):
        self.entries = entries
        self.calls = []

    def handle(self, url):
        self.calls.append(url)
        if url.endswith("get-sth"):
            return {"tree_size": len(self.entries)}
        if "get-entries" in url:
            q = dict(part.split("=") for part in url.split("?")[1].split("&"))
            start, end = int(q["start"]), int(q["end"])
            return {
                "entries": [
                    {"leaf_input": e, "extra_data": ""} for e in self.entries[start : end + 1]
                ]
            }
        raise RuntimeError("404")


def make_fetcher(logs, fail_urls=()):
    def fetch(url, timeout):
        for base, log in logs.items():
            if url.startswith(base):
                if any(url.startswith(f) for f in fail_urls):
                    raise RuntimeError("HTTP 503")
                return log.handle(url)
        raise RuntimeError("connection refused")

    return fetch


def sample_entries(n, prefix="host"):
    return [
        leaf_input(certificate(f"{prefix}{i}.example", [f"{prefix}{i}.example"]), i % 2)
        for i in range(n)
    ]


class TestCTLogTailer:
    def test_tails_from_recent_tail_and_dispatches(self):
        log = FakeLog(sample_entries(20))
        received = []
        tailer = CTLogTailer(
            received.append,
            logs=[{"name": "fake", "url": "https://fake.log/"}],
            fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=8,
            poll_interval=0,
            now=lambda: 0,
        )
        tailer.discover()
        assert tailer.logs[0]["cursor"] == 12  # starts batch_size behind the tree head
        assert tailer.poll_once() == 8
        assert [m["data"]["leaf_cert"]["all_domains"][0] for m in received] == [
            f"host{i}.example" for i in range(12, 20)
        ]
        assert tailer.poll_once() == 0  # caught up
        log.entries += sample_entries(3, "new")
        assert tailer.poll_once() == 3
        assert received[-1]["data"]["source"]["name"] == "fake"
        assert tailer.summary()["coverage"] == 100.0

    def test_skips_ahead_when_lagging(self):
        log = FakeLog(sample_entries(4))
        tailer = CTLogTailer(
            lambda m: None,
            logs=[{"name": "fake", "url": "https://fake.log/"}],
            fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=4,
            max_lag=10,
            now=lambda: 0,
        )
        tailer.discover()
        tailer.poll_once()
        log.entries += sample_entries(50, "burst")
        tailer.poll_once()
        assert tailer.stats["skipped"] > 0 and tailer.logs[0]["cursor"] == 54
        assert tailer.summary()["coverage"] < 100

    def test_unreachable_logs_are_dropped_and_errors_back_off(self):
        good = FakeLog(sample_entries(3))
        clock = {"t": 0.0}
        tailer = CTLogTailer(
            lambda m: None,
            logs=[
                {"name": "good", "url": "https://good.log/"},
                {"name": "dead", "url": "https://dead.log/"},
            ],
            fetcher=make_fetcher({"https://good.log/": good}),
            batch_size=2,
            now=lambda: clock["t"],
        )
        assert [entry["name"] for entry in tailer.discover()] == ["good"]
        # break the good log after discovery
        tailer.fetch = make_fetcher({"https://good.log/": good}, fail_urls=("https://good.log/",))
        assert tailer.poll_once() == 0
        assert tailer.logs[0]["status"].startswith("error") and tailer.logs[0]["next_at"] > 0
        assert tailer.poll_once() == 0  # still backing off, no request made
        assert tailer.stats["errors"] == 1

    def test_parse_errors_are_counted_not_fatal(self):
        log = FakeLog([base64.b64encode(b"garbage").decode()] + sample_entries(2))
        received = []
        tailer = CTLogTailer(
            received.append,
            logs=[{"name": "fake", "url": "https://fake.log/"}],
            fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=10,
            now=lambda: 0,
        )
        tailer.discover()
        tailer.poll_once()
        assert tailer.stats["parse_errors"] == 1 and len(received) == 2

    def test_run_with_iterations_sleeps_when_idle(self):
        log = FakeLog(sample_entries(2))
        sleeps = []
        tailer = CTLogTailer(
            lambda m: None,
            logs=[{"name": "fake", "url": "https://fake.log/"}],
            fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=4,
            poll_interval=0.5,
            sleep=sleeps.append,
            now=lambda: 0,
        )
        tailer.run(iterations=3)
        assert sleeps  # idle rounds slept

    def test_discovery_uses_log_list_then_fallback(self):
        now = datetime(2026, 9, 24, tzinfo=timezone.utc)
        log_list = {
            "operators": [
                {
                    "name": "Google",
                    "logs": [
                        {
                            "description": "Argon2026h2",
                            "url": "https://ct.googleapis.com/logs/us1/argon2026h2/",
                            "state": {"usable": {}},
                            "temporal_interval": {
                                "start_inclusive": "2026-07-01T00:00:00Z",
                                "end_exclusive": "2027-01-01T00:00:00Z",
                            },
                        },
                        {
                            "description": "Argon2025h1",
                            "url": "https://ct.googleapis.com/logs/us1/argon2025h1/",
                            "state": {"usable": {}},
                            "temporal_interval": {
                                "start_inclusive": "2025-01-01T00:00:00Z",
                                "end_exclusive": "2025-07-01T00:00:00Z",
                            },
                        },
                        {
                            "description": "Retired",
                            "url": "https://ct.googleapis.com/logs/retired/",
                            "state": {"retired": {}},
                        },
                    ],
                }
            ]
        }
        chosen = select_logs_from_list(log_list, now=now)
        assert [c["url"] for c in chosen] == ["https://ct.googleapis.com/logs/us1/argon2026h2/"]
        assert chosen[0]["name"] == "Google Argon2026h2"

        fetched = []

        def fetch(url, timeout):
            fetched.append(url)
            raise RuntimeError("offline")

        tailer = CTLogTailer(lambda m: None, fetcher=fetch)
        assert tailer.discover() == []  # nothing reachable, but every fallback shard was probed
        assert fetched[0].endswith("log_list.json")
        assert len(fetched) == 1 + len(FALLBACK_LOGS)


class TestMonitorIntegration:
    def test_monitor_matches_keywords_from_ct_entries(self):
        cfg = CertStreamConfig(keywords=["nbk", "kuwait"], heartbeat_interval=1)
        monitor = CertStreamMonitor(cfg)
        events = []
        monitor.add_callback(events.append)
        log = FakeLog(
            [
                leaf_input(certificate("login.nbk-secure.xyz", ["login.nbk-secure.xyz"]), 1),
                leaf_input(certificate("example.org", ["example.org"]), 0),
                leaf_input(
                    certificate(
                        "kuwait-visa.online", ["kuwait-visa.online", "www.kuwait-visa.online"]
                    ),
                    0,
                ),
            ]
        )
        monitor.build_ct_tailer(
            logs=[{"name": "fake", "url": "https://fake.log/"}],
            fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=10,
            sleep=lambda s: None,
            now=lambda: 0,
        )
        monitor.start_ct_logs(iterations=2)
        assert [e.domain for e in events] == [
            "login.nbk-secure.xyz",
            "kuwait-visa.online",
            "www.kuwait-visa.online",
        ]
        assert events[0].source == "fake" and events[0].issuer_name == "Let's Encrypt"
        stats = monitor.get_stats()
        assert (
            stats["total_certs"] == 3
            and stats["source"] == "ctlogs"
            and stats["ct"]["entries"] == 3
        )
        assert stats["ct_logs"] == ["fake"]

    def test_default_config_uses_ct_logs_and_kuwait_keywords(self):
        cfg = CertStreamConfig()
        assert cfg.source == "ctlogs"
        for kw in ("kuwait", "q8", "kwt", "knet", "sahel", "الكويت"):
            assert kw in cfg.keywords
