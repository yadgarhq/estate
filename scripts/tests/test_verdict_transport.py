"""`http_transport` against real sockets: the token stays on the API host.

GitHub answers an artifact download with a 302 to blob storage on another host.
urllib follows redirects by default and copies ordinary headers onto the new
request, so a token added the ordinary way would reach that host. Two local
`http.server`s stand in: the API on 127.0.0.1, the blob store on `localhost`
(a different host name, as the real store is).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import VERIFY_TOKEN

import verdict


def serve(respond):
    seen: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (http.server's name)
            seen.append({"path": self.path, "authorization": self.headers.get("Authorization")})
            status, headers, body = respond(self.path)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


@pytest.fixture
def hosts(monkeypatch):
    blob, blob_seen = serve(lambda _p: (200, {}, b"the-artifact-bytes"))
    blob_url = f"http://localhost:{blob.server_port}/store/7.zip"
    api, api_seen = serve(lambda _p: (302, {"Location": blob_url}, b""))
    monkeypatch.setattr(verdict, "API", f"http://127.0.0.1:{api.server_port}")
    yield api_seen, blob_seen, blob_url
    api.shutdown()
    blob.shutdown()


def test_the_transport_does_not_follow_a_redirect(hosts):
    api_seen, blob_seen, blob_url = hosts
    resp = verdict.http_transport(f"{verdict.API}/repos/x/actions/artifacts/7/zip", VERIFY_TOKEN)
    assert (resp.status, resp.location) == (302, blob_url)
    assert api_seen[0]["authorization"] == f"Bearer {VERIFY_TOKEN}"
    assert blob_seen == [], "the redirect was followed"


def test_the_download_hop_reaches_the_second_host_without_the_token(hosts):
    api_seen, blob_seen, _ = hosts
    gh = verdict.GitHub(verdict.http_transport, VERIFY_TOKEN, "argocd-verify")
    assert gh.download("/repos/x/actions/artifacts/7/zip") == b"the-artifact-bytes"
    assert api_seen[0]["authorization"] == f"Bearer {VERIFY_TOKEN}"
    assert [s["authorization"] for s in blob_seen] == [None]


def test_the_token_is_an_unredirected_header_even_if_a_redirect_were_followed(monkeypatch):
    # Belt and braces with `_NoRedirect`: each layer alone keeps the token home.
    monkeypatch.setattr(verdict, "API", "https://api.example")
    req = verdict.build_request("https://api.example/repos/x", VERIFY_TOKEN)
    assert req.unredirected_hdrs.get("Authorization") == f"Bearer {VERIFY_TOKEN}"
    assert "Authorization" not in req.headers
    assert "Authorization" not in verdict.build_request("https://blob.example/x", VERIFY_TOKEN).unredirected_hdrs
