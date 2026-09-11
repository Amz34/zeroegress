"""Egress jail tests: the block must be real, not a flag."""

import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zeroegress.jail import (  # noqa: E402
    EgressBlocked,
    EgressJail,
    block_probe,
    is_loopback_host,
    is_loopback_target,
)


class LoopbackHelpers(unittest.TestCase):
    def test_loopback_hosts(self):
        for host in ("127.0.0.1", "::1", "localhost", "[::1]", None, ""):
            self.assertTrue(is_loopback_host(host), host)

    def test_remote_hosts(self):
        for host in ("api.openai.com", "api.deepseek.com", "10.0.0.5", "192.168.1.10", "8.8.8.8"):
            self.assertFalse(is_loopback_host(host), host)

    def test_targets(self):
        self.assertTrue(is_loopback_target(("127.0.0.1", 11434)))
        self.assertTrue(is_loopback_target("/tmp/some.sock"))  # AF_UNIX
        self.assertFalse(is_loopback_target(("api.openai.com", 443)))


class JailBlocksEgress(unittest.TestCase):
    def test_connect_to_ip_is_blocked(self):
        with EgressJail(label="test") as jail:
            with self.assertRaises(EgressBlocked):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    sock.connect(("1.1.1.1", 443))
        self.assertEqual(jail.blocked_count, 1)
        self.assertEqual(jail.blocked[0]["target"], "1.1.1.1:443")

    def test_dns_lookup_is_blocked(self):
        with EgressJail(label="test") as jail:
            with self.assertRaises(EgressBlocked):
                socket.getaddrinfo("api.deepseek.com", 443)
        self.assertEqual(jail.blocked[0]["kind"], "getaddrinfo")

    def test_connect_ex_returns_refused_without_network(self):
        with EgressJail(label="test") as jail:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                code = sock.connect_ex(("8.8.8.8", 53))
        self.assertEqual(code, 111)
        self.assertEqual(jail.blocked_count, 1)

    def test_loopback_still_works(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            with EgressJail(label="test") as jail:
                client = socket.create_connection(("127.0.0.1", port), timeout=2)
                client.close()
            self.assertEqual(jail.blocked_count, 0)
            self.assertGreaterEqual(jail.allowed_loopback, 1)
        finally:
            server.close()

    def test_socket_layer_is_restored(self):
        original = socket.socket.connect
        with EgressJail(label="test"):
            self.assertIsNot(socket.socket.connect, original)
        self.assertIs(socket.socket.connect, original)

    def test_audit_log_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "nested" / "egress.jsonl"
            with EgressJail(audit_path=audit, label="audit"):
                with self.assertRaises(EgressBlocked):
                    socket.getaddrinfo("example.com", 443)
            rows = [json.loads(line) for line in audit.read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["action"], "blocked")
            self.assertEqual(rows[0]["label"], "audit")

    def test_block_probe_reports_real_blocks(self):
        with EgressJail(label="probe"):
            rows = block_probe(["api.openai.com", "1.1.1.1"], timeout=1.0)
        self.assertTrue(all(r["blocked"] for r in rows), rows)
        self.assertTrue(all("socket" in (r["mechanism"] or "") for r in rows), rows)


if __name__ == "__main__":
    unittest.main()
