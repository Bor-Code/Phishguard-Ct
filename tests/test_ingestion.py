import asyncio
import json
import pytest
from phishguard.ingestion.client import CertstreamClient
from phishguard.ingestion.parser import (
    clean_domain,
    extract_domains_from_leaf,
    extract_issuer_name,
    parse_certstream_message,
)


def test_clean_domain_valid():
    assert clean_domain("example.com") == "example.com"
    assert clean_domain("  EXAMPLE.COM  ") == "example.com"
    assert clean_domain("*.sub.example.com") == "sub.example.com"
    assert clean_domain(".example.org") == "example.org"


def test_clean_domain_invalid():
    assert clean_domain("") is None
    assert clean_domain("   ") is None
    assert clean_domain("nodotdomain") is None
    assert clean_domain("invalid domain.com") is None


def test_extract_domains_from_leaf():
    leaf = {
        "all_domains": ["direct.com"],
        "subject": {"CN": "subject.com"},
        "extensions": {"subjectAltName": "DNS:san1.com, DNS:san2.com, direct.com"},
    }
    extracted = extract_domains_from_leaf(leaf)
    assert extracted == ["direct.com", "subject.com", "san1.com", "san2.com"]


def test_extract_issuer_name():
    assert extract_issuer_name({"issuer": {"O": "Let's Encrypt", "CN": "R3"}}) == "Let's Encrypt"
    assert extract_issuer_name({"issuer": {"CN": "DigiCert"}}) == "DigiCert"
    assert extract_issuer_name({"issuer": "Custom CA"}) == "Custom CA"
    assert extract_issuer_name({}) is None


def test_parse_certstream_message_heartbeat():
    message = json.dumps({"message_type": "heartbeat"})
    assert parse_certstream_message(message) is None


def test_parse_certstream_message_invalid_json():
    assert parse_certstream_message("not valid json") is None
    assert parse_certstream_message("") is None


def test_parse_certstream_message_dns_entries():
    payload = json.dumps(
        {
            "message_type": "dns_entries",
            "data": ["login.secure-bank.com", "*.secure-bank.com", "invalid"],
        }
    )
    event = parse_certstream_message(payload)
    assert event is not None
    assert event.domains == ["login.secure-bank.com", "secure-bank.com"]
    assert event.source_name == "dns_entries"


def test_parse_certstream_message_valid():
    sample = {
        "message_type": "certificate_update",
        "data": {
            "update_type": "PrecertLogEntry",
            "leaf_cert": {
                "all_domains": ["login.secure-bank.com", "*.secure-bank.com"],
                "subject": {"CN": "login.secure-bank.com"},
                "fingerprint": "AA:BB:CC",
                "not_before": 1700000000,
                "not_after": 1710000000,
                "issuer": {"O": "Test CA", "CN": "Authority"},
            },
            "source": {"name": "TestLog"},
        },
    }
    event = parse_certstream_message(json.dumps(sample))
    assert event is not None
    assert event.domains == ["login.secure-bank.com", "secure-bank.com"]
    assert event.issuer == "Test CA"
    assert event.fingerprint == "AA:BB:CC"
    assert event.not_before == 1700000000.0
    assert event.not_after == 1710000000.0
    assert event.source_name == "TestLog"


class MockWebSocket:
    def __init__(self, messages):
        self.messages = list(messages)
        self.closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.messages or self.closed:
            raise StopAsyncIteration
        return self.messages.pop(0)

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_certstream_client_consume():
    sample_payload = json.dumps(
        {
            "message_type": "certificate_update",
            "data": {
                "leaf_cert": {
                    "all_domains": ["account.target.com"],
                    "issuer": {"CN": "Sample CA"},
                }
            },
        }
    )
    queue = asyncio.Queue()
    client = CertstreamClient(queue=queue)
    client._running = True
    mock_ws = MockWebSocket([sample_payload])

    await client._consume_websocket(mock_ws)

    assert not queue.empty()
    event = await queue.get()
    assert event.domains == ["account.target.com"]
    assert event.issuer == "Sample CA"


@pytest.mark.asyncio
async def test_certstream_client_lifecycle():
    client = CertstreamClient(url="wss://dummy.local")
    await client.start()
    assert client._running is True
    await client.stop()
    assert client._running is False
