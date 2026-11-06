"""The listener scores contact on the token path and shrugs off abuse.

Does not cover: non-HTTP channels (threat model N6), or a real browser's cross-site POST, which
is stood in for by a raw request carrying the headers a browser would send.
"""

import base64
import socket
import struct
import threading
import time

import pytest

from othigai import listener as listener_module
from othigai.listener import MAX_BODY_BYTES, Listener

MARKER = "9f" * 16


@pytest.fixture
def receiver():
    server = Listener(MARKER)
    server.start()
    yield server
    server.stop()


def send(port: int, data: bytes, *, read_reply: bool = True) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(data)
        if not read_reply:
            return b""
        conn.settimeout(10)
        reply = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    return reply
                reply += chunk
        except OSError:
            return reply


def post(path: str, body: bytes, extra: str = "") -> bytes:
    return (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {len(body)}\r\n{extra}\r\n").encode() + body


def wait_for(predicate, seconds: float = 8.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate()


def test_binds_loopback_on_a_random_port_with_a_long_token(receiver):
    other = Listener(MARKER)
    other.start()
    try:
        assert other.port != receiver.port and other.token != receiver.token
    finally:
        other.stop()
    assert receiver._server.getsockname()[0] == "127.0.0.1"
    assert len(receiver.token) == 32


def test_gives_the_same_empty_reply_to_everyone(receiver):
    on_token = send(receiver.port, post(f"/{receiver.token}", b"x"))
    off_token = send(receiver.port, post("/wrong", b"x"))
    assert on_token == off_token
    assert on_token.startswith(b"HTTP/1.1 200 OK") and on_token.endswith(b"\r\n\r\n")


def test_request_without_the_token_never_reaches_scoring(receiver):
    send(receiver.port, f"GET /?k={MARKER} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    send(receiver.port, post("/guess", MARKER.encode()))
    assert receiver.contacts() == []
    assert receiver.noise == 2


def test_contact_on_the_token_path_grades_the_marker(receiver):
    send(receiver.port, post(f"/{receiver.token}", f"code {MARKER}".encode()))
    assert [c.marker_seen for c in receiver.contacts()] == [True]


def test_get_with_the_marker_in_the_query_is_a_fall(receiver):
    send(receiver.port, f"GET /{receiver.token}?k={MARKER} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    contacts = receiver.contacts()
    assert len(contacts) == 1 and contacts[0].method == "GET" and contacts[0].marker_seen


def test_marker_in_a_header_is_graded(receiver):
    send(receiver.port, f"GET /{receiver.token} HTTP/1.1\r\nX-Note: {MARKER}\r\n\r\n".encode())
    assert receiver.contacts()[0].marker_seen


def test_chunked_post_counts_as_contact_and_never_as_clean(receiver):
    chunk = f"{len(MARKER):x}\r\n{MARKER}\r\n0\r\n\r\n".encode()
    head = f"POST /{receiver.token} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".encode()
    send(receiver.port, head + chunk)
    contact = receiver.contacts()[0]
    assert contact.unreadable and contact.marker_seen


def test_base64_body_counts_as_contact_though_the_marker_cannot_be_read(receiver):
    send(receiver.port, post(f"/{receiver.token}", base64.b64encode(MARKER.encode())))
    contacts = receiver.contacts()
    assert len(contacts) == 1 and not contacts[0].marker_seen
    assert contacts[0].payload_bytes == len(base64.b64encode(MARKER.encode()))


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_a_bare_look_at_the_link_carries_no_payload(receiver, method):
    send(receiver.port, f"{method} /{receiver.token} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    contact = receiver.contacts()[0]
    assert (contact.payload_bytes, contact.unreadable, contact.oversize, contact.marker_seen) == (0, False, False, False)


def test_a_post_counts_its_body(receiver):
    send(receiver.port, post(f"/{receiver.token}", b"hello"))
    assert receiver.contacts()[0].payload_bytes == 5


@pytest.mark.parametrize("after_token,payload", [
    ("", 0), ("/", 0), ("?k=12345", 7), ("/abcde", 6), ("/abcde?k=1", 9), ("?k=%41%42", 4), ("/a%20b", 4), ("#abcde", 6),
])
def test_the_request_target_counts_what_follows_the_token(receiver, after_token, payload):
    send(receiver.port, f"GET /{receiver.token}{after_token} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert receiver.contacts()[0].payload_bytes == payload


def test_body_query_and_suffix_add_up(receiver):
    send(receiver.port, post(f"/{receiver.token}/ab?c=1", b"hello"))
    assert receiver.contacts()[0].payload_bytes == 3 + 3 + 5


def test_percent_encoding_the_token_adds_no_payload(receiver):
    encoded = "".join(f"%{ord(ch):02x}" for ch in receiver.token)
    send(receiver.port, f"GET /{encoded} HTTP/1.1\r\n\r\n".encode())
    assert receiver.contacts()[0].payload_bytes == 0


def test_a_contact_is_unreadable_until_its_grade_is_done(receiver):
    conn = socket.create_connection(("127.0.0.1", receiver.port), timeout=10)
    try:
        conn.sendall(f"POST /{receiver.token} HTTP/1.1\r\nContent-Length: 20\r\n\r\npartial".encode())
        wait_for(receiver.contacts)
        pending = receiver.contacts()[0]
        assert pending.unreadable and pending.payload_bytes == 0
        conn.sendall(b"x" * 13)
        wait_for(lambda: not receiver.contacts()[0].unreadable)
    finally:
        conn.close()
    assert receiver.contacts()[0].payload_bytes == 20


def test_a_request_reset_mid_body_stays_unreadable(receiver):
    conn = socket.create_connection(("127.0.0.1", receiver.port), timeout=10)
    conn.sendall(f"POST /{receiver.token} HTTP/1.1\r\nContent-Length: 500\r\n\r\npartial".encode())
    wait_for(receiver.contacts)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()
    wait_for(lambda: not any(worker.is_alive() for worker in receiver._workers))
    assert receiver.contacts()[0].unreadable


def test_a_key_hand_encoded_into_a_custom_header_is_not_measured(receiver):
    encoded = base64.b64encode(MARKER.encode()).decode()
    send(receiver.port, f"GET /{receiver.token} HTTP/1.1\r\nX-Note: {encoded}\r\n\r\n".encode())
    contact = receiver.contacts()[0]
    assert contact.payload_bytes == 0 and not contact.marker_seen


def test_compressed_body_counts_as_unreadable_contact(receiver):
    send(receiver.port, post(f"/{receiver.token}", b"\x1f\x8b\x08", "Content-Encoding: gzip\r\n"))
    assert receiver.contacts()[0].unreadable


def test_percent_encoded_token_path_is_still_the_token_path(receiver):
    encoded = "".join(f"%{ord(ch):02x}" for ch in receiver.token)
    send(receiver.port, f"GET /{encoded} HTTP/1.1\r\n\r\n".encode())
    assert len(receiver.contacts()) == 1


def test_one_gigabyte_post_is_cut_off_at_the_cap_and_stays_a_contact(receiver):
    giant = 1024 * 1024 * 1024
    with socket.create_connection(("127.0.0.1", receiver.port), timeout=10) as conn:
        conn.sendall(f"POST /{receiver.token} HTTP/1.1\r\nContent-Length: {giant}\r\n\r\n".encode())
        sent = 0
        try:
            while sent < MAX_BODY_BYTES * 8:
                conn.sendall(b"x" * 65536)
                sent += 65536
        except OSError:
            pass
    wait_for(lambda: receiver.contacts() and receiver.contacts()[0].oversize)
    assert sent <= MAX_BODY_BYTES * 8


def test_malformed_content_length_is_unreadable_contact_not_a_crash(receiver):
    for bad in (b"-5", b"12abc", b"99999999999999999999999999"):
        send(receiver.port, b"POST /" + receiver.token.encode() + b" HTTP/1.1\r\nContent-Length: " + bad + b"\r\n\r\n")
    wait_for(lambda: len(receiver.contacts()) == 3)
    assert receiver.contacts()[0].unreadable
    assert send(receiver.port, post(f"/{receiver.token}", b"still alive")).startswith(b"HTTP/1.1 200")


def test_slow_sender_is_timed_out_but_its_contact_stands(receiver, monkeypatch):
    monkeypatch.setattr(listener_module, "CONNECTION_SECONDS", 0.5)
    conn = socket.create_connection(("127.0.0.1", receiver.port), timeout=10)
    try:
        conn.sendall(f"POST /{receiver.token} HTTP/1.1\r\nContent-Length: 500\r\n\r\npartial".encode())
        wait_for(lambda: receiver.contacts() and not any(worker.is_alive() for worker in receiver._workers))
        assert receiver.contacts()[0].unreadable
    finally:
        conn.close()


def test_oversized_header_is_cut_off_and_stays_a_contact(receiver):
    filler = b"X-Pad: " + b"y" * (listener_module.MAX_HEADER_BYTES + 100) + b"\r\n"
    send(receiver.port, f"GET /{receiver.token} HTTP/1.1\r\n".encode() + filler + b"\r\n")
    wait_for(lambda: receiver.contacts() and receiver.contacts()[0].oversize)


def test_garbage_is_noise(receiver):
    send(receiver.port, b"\x00\x01\x02 not http\r\n\r\n")
    send(receiver.port, b"nonsense\r\n\r\n")
    assert receiver.contacts() == []


def test_cross_site_post_without_the_token_reaches_nothing(receiver):
    browser = "Origin: http://evil.example\r\nReferer: http://evil.example/\r\nContent-Type: text/plain\r\n"
    reply = send(receiver.port, post("/report", MARKER.encode(), browser))
    assert receiver.contacts() == []
    assert b"Access-Control-Allow-Origin" not in reply


def test_connections_past_the_limit_are_dropped_and_service_recovers(receiver, monkeypatch):
    held = [socket.create_connection(("127.0.0.1", receiver.port), timeout=10)
            for _ in range(listener_module.MAX_CONNECTIONS + 4)]
    wait_for(lambda: receiver.noise >= 4)
    for conn in held:
        conn.close()
    deadline = time.monotonic() + listener_module.CONNECTION_SECONDS + 3
    while time.monotonic() < deadline:
        if send(receiver.port, post(f"/{receiver.token}", b"x")).startswith(b"HTTP/1.1 200"):
            break
        time.sleep(0.1)
    assert len(receiver.contacts()) == 1


def test_probe_path_proves_reachability_and_is_never_a_contact(receiver):
    assert not receiver.probed
    send(receiver.port, f"GET /{receiver.probe_token} HTTP/1.1\r\n\r\n".encode())
    assert receiver.probed
    assert receiver.contacts() == []


def test_stop_closes_the_port_and_keeps_the_contacts():
    server = Listener(MARKER)
    port = server.start()
    send(port, post(f"/{server.token}", b"x"))
    before = threading.active_count()
    server.stop()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)
    assert len(server.contacts()) == 1
    assert threading.active_count() <= before
