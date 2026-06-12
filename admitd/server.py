"""HTTPS AdmissionReview webhook server for admitd.

Standard library only (``http.server`` + ``ssl``). Kubernetes posts an
``AdmissionReview`` to ``/validate`` (or ``/mutate``); admitd evaluates the
embedded object against the loaded policies and returns an ``AdmissionReview``
response carrying ``allowed`` plus, for mutate mode, a base64 JSONPatch.

Endpoints:
    POST /validate   — allow/deny only
    POST /mutate     — allow + JSONPatch (requires --mutate)
    GET  /healthz    — liveness probe ("ok")

TLS is required for a real cluster webhook (the API server only speaks HTTPS).
For a smoke test, ``self_test`` runs the server over plain HTTP on localhost,
posts one AdmissionReview, asserts the response, and shuts down.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List

from admitd.core import (
    TOOL_NAME,
    TOOL_VERSION,
    Policy,
    admission_response,
    evaluate_object,
    parse_objects,
)


def _make_handler(policies: List[Policy], mutate: bool):
    class AdmissionHandler(BaseHTTPRequestHandler):
        server_version = f"{TOOL_NAME}/{TOOL_VERSION}"

        def log_message(self, fmt, *a):  # quiet by default
            pass

        def _send_json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("/healthz", "/health"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):  # noqa: N802
            path = self.path.rstrip("/")
            do_mutate = mutate and path == "/mutate"
            if path not in ("/validate", "/mutate"):
                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            uid = ""
            try:
                review = json.loads(raw)
                uid = ((review.get("request") or {}).get("uid")) or ""
            except json.JSONDecodeError:
                review = None

            objs = parse_objects(raw, source="<webhook>")
            if not objs:
                # No object to evaluate → allow (fail-open is the conventional
                # default for a webhook that received an unparseable body).
                self._send_json(200, {
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {"uid": uid, "allowed": True,
                                 "warnings": ["admitd: no object to evaluate"]},
                })
                return

            obj, _ = objs[0]
            decision = evaluate_object(obj, policies, source="<webhook>")
            if not do_mutate:
                decision.patches = []  # validate-only: never return a patch
            resp = admission_response(decision, uid=uid)
            self._send_json(200, resp)

    return AdmissionHandler


def serve(policies: List[Policy], host: str = "0.0.0.0", port: int = 8443,
          tls_cert: str = None, tls_key: str = None, mutate: bool = False) -> int:
    handler = _make_handler(policies, mutate)
    httpd = ThreadingHTTPServer((host, port), handler)

    scheme = "http"
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        except (OSError, ssl.SSLError) as exc:
            print(f"error loading TLS material: {exc}", file=sys.stderr)
            return 2
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    elif tls_cert or tls_key:
        print("error: --tls-cert and --tls-key must be given together.", file=sys.stderr)
        return 2
    else:
        print("warning: serving over plain HTTP (no TLS). A real Kubernetes "
              "webhook requires HTTPS — pass --tls-cert/--tls-key.",
              file=sys.stderr)

    print(f"{TOOL_NAME} {TOOL_VERSION} webhook listening on "
          f"{scheme}://{host}:{port}  (POST /validate"
          + (", /mutate" if mutate else "") + f"; {len(policies)} policies)",
          file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.", file=sys.stderr)
    finally:
        httpd.server_close()
    return 0


_PRIVILEGED_REVIEW = {
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "self-test-uid-0001",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "operation": "CREATE",
        "object": {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "selftest", "namespace": "default"},
            "spec": {"containers": [{
                "name": "app", "image": "nginx:latest",
                "securityContext": {"privileged": True},
            }]},
        },
    },
}


def self_test(policies: List[Policy], mutate: bool = False) -> bool:
    """Bind on localhost over plain HTTP, post one AdmissionReview, verify, stop."""
    import urllib.request

    handler = _make_handler(policies, mutate)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.socket.getsockname()[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    ok = False
    try:
        # health probe
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
            health_ok = r.read() == b"ok"
        # validate a deliberately privileged pod → must be denied
        data = json.dumps(_PRIVILEGED_REVIEW).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/validate", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            resp = json.loads(r.read().decode("utf-8"))
        response = resp.get("response") or {}
        ok = (
            health_ok
            and resp.get("kind") == "AdmissionReview"
            and response.get("uid") == "self-test-uid-0001"
            and response.get("allowed") is False
        )
        if ok:
            print(f"{TOOL_NAME} self-test OK: privileged Pod denied on :{port} "
                  f"(reason: {(response.get('status') or {}).get('message', '')[:80]}...)",
                  file=sys.stderr)
        else:
            print(f"{TOOL_NAME} self-test FAILED: {json.dumps(resp)}", file=sys.stderr)
    except (OSError, socket.error, ValueError) as exc:
        print(f"{TOOL_NAME} self-test error: {exc}", file=sys.stderr)
        ok = False
    finally:
        httpd.shutdown()
        httpd.server_close()
    return ok
