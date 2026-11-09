"""The stdlib transport against a real local HTTP server."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bahari_sso import BahariError, UrllibHttpClient


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        status = 404 if self.path == "/missing" else 200
        body = ('{"sdk": "%s", "accept": "%s"}' % (self.headers.get("X-Bahari-SDK"), self.headers.get("Accept"))).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Bahari-SDK-Status", "ok")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()


def test_transport_returns_statuses_and_lowercases_headers(server):
    http = UrllibHttpClient()
    response = http.send("GET", server + "/ok", {"Accept": "application/json", "X-Bahari-SDK": "bahari-sso/0.1.0"})
    assert response.status == 200 and response.ok
    assert response.json() == {"sdk": "bahari-sso/0.1.0", "accept": "application/json"}
    assert response.header("x-bahari-sdk-status") == "ok" and "x-bahari-sdk-status" in response.headers
    assert http.send("GET", server + "/missing").status == 404
    assert http.send("POST", server + "/echo", {"Content-Type": "text/plain"}, "hello").body == "hello"


def test_transport_never_follows_redirects(server):
    response = UrllibHttpClient().send("GET", server + "/redirect")
    assert response.status == 302 and response.header("location") == "/target"


def test_transport_rejects_other_schemes_and_unreachable_hosts():
    with pytest.raises(BahariError):
        UrllibHttpClient().send("GET", "file:///etc/passwd")
    with pytest.raises(BahariError):
        UrllibHttpClient(connect_timeout=1, timeout=2).send("GET", "http://127.0.0.1:9/")
