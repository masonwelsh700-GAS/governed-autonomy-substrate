import argparse
import hmac
import json
import os
import ssl
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .admin_ui import render_admin_ui
from .bootstrap import build_runtime_service
from .deployment import BoundedRateLimiter, TLSConfig, correlation_id, security_headers
from .errors import AuthorizationError
from .health import health_report
from .identity import IdentityValidationError, OIDCValidator, UrlJWKSProvider
from .issuer import PolicyDeniedError
from .mesh import GovernanceInput
from .service import GovernedService


class AuthenticatedAPI:
    def __init__(self, service: GovernedService, *, bearer_token: str | None = None,
                 oidc_validator: OIDCValidator | None = None, operator_token: str | None = None,
                 operator_role: str = "gas-admin", max_body_bytes: int = 64 * 1024,
                 rate_limit: int = 120) -> None:
        if not bearer_token and oidc_validator is None:
            raise ValueError("bearer_token or oidc_validator is required")
        if max_body_bytes <= 0 or rate_limit <= 0:
            raise ValueError("body and rate limits must be positive")
        self.service = service
        self.bearer_token = bearer_token
        self.oidc_validator = oidc_validator
        self.operator_token = operator_token
        self.operator_role = operator_role
        self.max_body_bytes = max_body_bytes
        self.rate_limiter = BoundedRateLimiter(rate_limit)

    def handler(self) -> type[BaseHTTPRequestHandler]:
        api = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "GovernedAutonomy/0.2"

            def do_GET(self) -> None:
                if not api._allowed(self):
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
                    return
                if not api._authenticated(self):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                if self.path.startswith("/admin") and not api._operator_authorized(self):
                    self._send(HTTPStatus.FORBIDDEN, {"error": "operator authorization required"})
                    return
                if self.path == "/admin":
                    body = render_admin_ui()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    for key, value in security_headers().items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path in {"/health", "/livez", "/readyz", "/startupz"}:
                    report = health_report(replay_log=api.service.boundary.replay_log,
                        trust_store=api.service.boundary.trust_store,
                        policy_registry=api.service.policies,
                        mesh_source_registry=api.service.mesh_source_registry)
                    if self.path == "/livez":
                        report = {"ok": True, "status": "live"}
                    elif self.path == "/startupz":
                        report = {"ok": True, "status": "started"}
                    elif self.path == "/readyz" and not report["ok"]:
                        self._send(HTTPStatus.SERVICE_UNAVAILABLE, report)
                        return
                    self._send(HTTPStatus.OK, report)
                    return
                if self.path == "/audit":
                    self._send(HTTPStatus.OK, api.service.audit_report())
                elif self.path in {"/admin/keys", "/status/keys"}:
                    self._send(HTTPStatus.OK, api.service.admin_status().get("keys", {}))
                elif self.path == "/admin/keys/active":
                    keys = api.service.admin_status()["keys"]
                    self._send(HTTPStatus.OK, {"active_key_id": keys["active_key_id"]})
                elif self.path == "/admin/keys/revoked":
                    keys = api.service.admin_status()["keys"]
                    self._send(HTTPStatus.OK, {"revoked_key_ids": keys["revoked_key_ids"]})
                elif self.path in {"/admin/policies/proposals", "/status/policies", "/admin/proposals"}:
                    self._send(HTTPStatus.OK, api.service.admin_status().get("policies", {}))
                elif self.path == "/admin/policies":
                    self._send(HTTPStatus.OK, {"policies": api.service.policies.to_dict()})
                elif self.path == "/admin/metrics":
                    self._send(HTTPStatus.OK, api.service.audit_report()["audit_summary"])
                elif self.path == "/openapi.json":
                    self._send(HTTPStatus.OK, API_SCHEMA)
                else:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

            def do_POST(self) -> None:
                if not api._allowed(self):
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
                    return
                if not api._authenticated(self):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                try:
                    payload = api._read_json(self)
                    if self.path in {"/authorize", "/api/v1/authorize"}:
                        raw = payload.get("mesh_inputs")
                        mesh = tuple(GovernanceInput.from_dict(item) for item in raw) if raw is not None else None
                        result = api.service.authorize(payload["request"], payload["policy_id"],
                            ttl_seconds=payload.get("ttl_seconds", 300),
                            approvals=payload.get("approvals"), mesh_inputs=mesh).to_dict()
                        self._send(HTTPStatus.OK, result)
                    elif self.path in {"/execute", "/api/v1/execute"}:
                        self._send(HTTPStatus.OK, {"result": api.service.execute_dict(payload["artifact"])})
                    else:
                        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                except PolicyDeniedError as exc:
                    self._send(HTTPStatus.FORBIDDEN, {"error": "policy denied", "decision": exc.decision})
                except (AuthorizationError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                    self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid request"})

            def log_message(self, *_: Any) -> None:
                return

            def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("X-Request-ID", api._request_id(self))
                for key, value in security_headers().items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(encoded)

        return Handler

    def _authenticated(self, request: BaseHTTPRequestHandler) -> bool:
        supplied = request.headers.get("Authorization", "")
        if self.oidc_validator is not None and supplied.startswith("Bearer "):
            try:
                request.gas_identity = self.oidc_validator.validate(supplied[7:].strip())  # type: ignore[attr-defined]
            except IdentityValidationError:
                return False
            return True
        if self.operator_token and hmac.compare_digest(supplied, f"Bearer {self.operator_token}"):
            return True
        return bool(self.bearer_token) and (hmac.compare_digest(supplied, f"Bearer {self.bearer_token}") or hmac.compare_digest(supplied, self.bearer_token))

    def _operator_authorized(self, request: BaseHTTPRequestHandler) -> bool:
        identity = getattr(request, "gas_identity", None)
        if identity is not None:
            roles = identity.claims.get("roles", [])
            roles = [roles] if isinstance(roles, str) else roles
            scopes = identity.claims.get("scope", "")
            scopes = scopes.split() if isinstance(scopes, str) else scopes
            return self.operator_role in roles or "gas.admin" in scopes
        supplied = request.headers.get("Authorization", "")
        return bool(self.operator_token) and hmac.compare_digest(supplied, f"Bearer {self.operator_token}")

    def _allowed(self, request: BaseHTTPRequestHandler) -> bool:
        return self.rate_limiter.allow(request.client_address[0])

    @staticmethod
    def _request_id(request: BaseHTTPRequestHandler) -> str:
        return correlation_id(request.headers.get("X-Request-ID"))

    def _read_json(self, request: BaseHTTPRequestHandler) -> dict[str, Any]:
        header = request.headers.get("Content-Length")
        if header is None:
            raise ValueError("Content-Length is required")
        length = int(header)
        if length < 0 or length > self.max_body_bytes:
            raise ValueError("request body exceeds size limit")
        payload = json.loads(request.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("request JSON must be an object")
        return payload


def parse_server_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Governed Autonomy HTTP API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bearer-token", default=os.environ.get("GOVERNED_AUTONOMY_BEARER_TOKEN"))
    parser.add_argument("--oidc-issuer", default=os.environ.get("OIDC_ISSUER"))
    parser.add_argument("--oidc-audience", default=os.environ.get("OIDC_AUDIENCE"))
    parser.add_argument("--oidc-jwks-url", default=os.environ.get("OIDC_JWKS_URL"))
    parser.add_argument("--operator-token", default=os.environ.get("GOVERNED_AUTONOMY_OPERATOR_TOKEN"))
    parser.add_argument("--operator-role", default=os.environ.get("OIDC_OPERATOR_ROLE", "gas-admin"))
    parser.add_argument("--max-body-bytes", type=int, default=64 * 1024)
    parser.add_argument("--rate-limit", type=int, default=120)
    return parser.parse_args(argv)


def create_server(service: GovernedService, *, bearer_token: str, host: str = "127.0.0.1", port: int = 0,
                  max_body_bytes: int = 64 * 1024, rate_limit: int = 120, tls: TLSConfig | None = None,
                  oidc_validator: OIDCValidator | None = None, operator_token: str | None = None,
                  operator_role: str = "gas-admin") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), AuthenticatedAPI(service, bearer_token=bearer_token,
        oidc_validator=oidc_validator, operator_token=operator_token, operator_role=operator_role,
        max_body_bytes=max_body_bytes, rate_limit=rate_limit).handler())
    if tls is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        minimum = {"TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}.get(tls.min_version)
        if minimum is None:
            server.server_close()
            raise ValueError("tls.min_version must be TLSv1.2 or TLSv1.3")
        context.minimum_version = minimum
        context.load_cert_chain(certfile=tls.certfile, keyfile=tls.keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_server_args(argv)
    oidc_args = (args.oidc_issuer, args.oidc_audience, args.oidc_jwks_url)
    if any(oidc_args) and not all(oidc_args):
        raise SystemExit("OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL must be configured together")
    oidc = OIDCValidator(issuer=args.oidc_issuer, audience=args.oidc_audience,
        jwks_provider=UrlJWKSProvider(args.oidc_jwks_url)) if all(oidc_args) else None
    if not args.bearer_token and oidc is None:
        raise SystemExit("GOVERNED_AUTONOMY_BEARER_TOKEN or complete OIDC configuration is required")
    service, _, _ = build_runtime_service()
    server = create_server(service, bearer_token=args.bearer_token, oidc_validator=oidc,
        operator_token=args.operator_token, operator_role=args.operator_role, host=args.host,
        port=args.port, max_body_bytes=args.max_body_bytes, rate_limit=args.rate_limit)
    print(f"Serving Governed Autonomy HTTP API on http://{args.host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


API_SCHEMA = {"openapi": "3.0.0", "info": {"title": "Governed Autonomy Substrate", "version": "1.0"},
              "paths": {"/api/v1/authorize": {"post": {}}, "/api/v1/execute": {"post": {}},
                        "/admin/keys": {"get": {}}, "/admin/keys/active": {"get": {}},
                        "/admin/keys/revoked": {"get": {}}, "/admin/policies/proposals": {"get": {}},
                        "/status/keys": {"get": {}}, "/status/policies": {"get": {}},
                        "/health": {"get": {}}, "/readyz": {"get": {}}}}
