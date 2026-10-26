"""Localhost mock LLM endpoint — stdlib http.server, zero external deps.

Used by triage integration tests; CI makes no live API calls (§5 contract).
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockLLMServer:
    """Scriptable single-endpoint server on an ephemeral localhost port."""

    def __init__(self) -> None:
        self.response_body = "{}"
        self.status = 200
        self.requests: list[dict] = []
        self._server = HTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 — stdlib API
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                outer.requests.append(json.loads(body))
                payload = outer.response_body.encode("utf-8")
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence test output
                pass

        return H

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1/complete"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def respond_with(self, obj_or_str, status: int = 200) -> None:
        self.status = status
        self.response_body = (obj_or_str if isinstance(obj_or_str, str)
                              else json.dumps(obj_or_str))
