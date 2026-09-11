"""Local model client tests - the endpoint guard is the important one."""

import contextlib
import http.server
import json
import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zeroegress import local_llm  # noqa: E402
from zeroegress.local_llm import NonLocalEndpoint  # noqa: E402


class EndpointGuard(unittest.TestCase):
    def test_cloud_endpoints_are_refused(self):
        for host in ("https://api.openai.com/v1", "https://api.deepseek.com", "http://8.8.8.8:11434"):
            with self.assertRaises(NonLocalEndpoint, msg=host):
                local_llm.chat([{"role": "user", "content": "hi"}], host=host)

    def test_loopback_endpoints_are_accepted(self):
        for host in ("http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:8080"):
            self.assertTrue(local_llm._assert_local(host).startswith("http"))

    def test_bad_scheme_is_refused(self):
        with self.assertRaises(NonLocalEndpoint):
            local_llm._assert_local("ftp://127.0.0.1:11434")


class DownServer(unittest.TestCase):
    def test_available_is_empty_when_nothing_listens(self):
        # Bind and close to obtain a port that is (almost certainly) free.
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        self.assertEqual(local_llm.available(f"http://127.0.0.1:{port}", timeout=1.0), [])

    def test_health_reports_down(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        report = local_llm.health(f"http://127.0.0.1:{port}")
        self.assertFalse(report["up"])
        self.assertEqual(report["models"], [])


class FakeOllamaServer(unittest.TestCase):
    """A tiny stand-in for /api/chat so the client path is covered without Ollama."""

    def setUp(self):
        payload = {"model": "test-model", "message": {"content": " local answer "}, "done_reason": "stop"}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence
                return

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_chat_parses_local_reply(self):
        reply = local_llm.chat(
            [{"role": "user", "content": "hi"}],
            model="test-model",
            host=f"http://127.0.0.1:{self.port}",
            timeout=5,
        )
        self.assertEqual(reply.text, "local answer")
        self.assertEqual(reply.model, "test-model")

    def test_chat_works_inside_the_jail(self):
        from zeroegress.jail import EgressJail

        with EgressJail(label="test") as jail:
            reply = local_llm.chat(
                [{"role": "user", "content": "hi"}],
                model="test-model",
                host=f"http://127.0.0.1:{self.port}",
                timeout=5,
            )
        self.assertEqual(reply.text, "local answer")
        self.assertEqual(jail.blocked_count, 0)


if __name__ == "__main__":
    unittest.main()
