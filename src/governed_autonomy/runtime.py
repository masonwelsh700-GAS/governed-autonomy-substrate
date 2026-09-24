"""Production runtime configuration and composition.

This module keeps deployment configuration explicit and fail-closed while leaving
provider-specific KMS/HSM implementations behind the :class:`Signer` protocol.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .engine import ExecutionBoundary
from .issuer import AuthorizationIssuer
from .platform_admin import PolicyChangeManager
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog
from .service import GovernedService
from .signing import Signer
from .storage import PostgresReplayLog, PostgresTrustStore
from .trust import TrustStore


@dataclass(frozen=True)
class RuntimeConfig:
    """Validated settings required to start a durable runtime."""

    mode: str
    database_url: str
    issuer_key_id: str | None
    issuer_private_key: str | None
    policy_approval_quorum: int
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    tenant_id: str | None = None
    service_name: str = "governed-autonomy"
    environment: str = "prod"

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "RuntimeConfig":
        env = os.environ if environ is None else environ
        mode = env.get("GAS_RUNTIME_MODE", "postgres").lower()
        if mode not in {"postgres", "memory"}:
            raise RuntimeError("GAS_RUNTIME_MODE must be postgres or memory")

        database_url = env.get("DATABASE_URL", "")
        key_id = env.get("GAS_ISSUER_KEY_ID")
        private_key = env.get("GAS_ISSUER_PRIVATE_KEY")
        if mode == "postgres" and not database_url:
            raise RuntimeError("DATABASE_URL is required in postgres runtime mode")
        if mode == "postgres" and not (key_id and private_key):
            raise RuntimeError(
                "GAS_ISSUER_KEY_ID and GAS_ISSUER_PRIVATE_KEY are required in "
                "postgres runtime mode unless a signer is injected"
            )

        try:
            quorum = int(env.get("GAS_POLICY_APPROVAL_QUORUM", "2"))
        except ValueError as exc:
            raise RuntimeError("GAS_POLICY_APPROVAL_QUORUM must be an integer") from exc
        if quorum <= 0:
            raise RuntimeError("GAS_POLICY_APPROVAL_QUORUM must be positive")

        oidc_values = tuple(env.get(name) for name in ("OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_JWKS_URL"))
        if any(oidc_values) and not all(oidc_values):
            raise RuntimeError("OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL must be configured together")

        return cls(
            mode=mode,
            database_url=database_url,
            issuer_key_id=key_id,
            issuer_private_key=private_key,
            policy_approval_quorum=quorum,
            oidc_issuer=oidc_values[0],
            oidc_audience=oidc_values[1],
            oidc_jwks_url=oidc_values[2],
            tenant_id=env.get("TENANT_ID"),
            service_name=env.get("GAS_SERVICE_NAME", "governed-autonomy"),
            environment=env.get("GAS_ENVIRONMENT", "prod"),
        )


@dataclass
class ProductionRuntime:
    """Durable service composition and its governance administration boundary."""

    config: RuntimeConfig
    service: GovernedService
    signer: Signer
    replay_log: ReplayLog
    trust_store: TrustStore
    policy_manager: PolicyChangeManager

    @classmethod
    def create(
        cls,
        *,
        config: RuntimeConfig | None = None,
        signer: Signer | None = None,
        connector: Callable[[str], Any] | None = None,
    ) -> "ProductionRuntime":
        config = config or RuntimeConfig.from_env()
        if config.mode == "memory":
            raise RuntimeError("ProductionRuntime requires postgres runtime mode")

        if signer is None:
            from .crypto import KeyPair

            signer = KeyPair.from_private_key_b64(
                config.issuer_key_id, config.issuer_private_key
            )
        if connector is None:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("install the postgres extra to use postgres runtime mode") from exc
            connector = psycopg.connect

        connection = connector(config.database_url)
        replay_log = PostgresReplayLog(connection)
        trust_store = PostgresTrustStore(connection)
        existing = trust_store.to_dict()
        if signer.key_id in existing["revoked"]:
            replay_log.close()
            raise RuntimeError(f"configured issuer key is revoked: {signer.key_id}")
        if trust_store.resolve(signer.key_id) is None:
            trust_store.add(
                signer.key_id,
                Ed25519PublicKey.from_public_bytes(signer.public_key_bytes()),
            )

        policies = PolicyRegistry(
            (Policy("demo-files-v1", ("write_file",), {"write_file": ("path", "content")},
                    {"write_file": {"path": "out.txt"}}),)
        )
        manager = PolicyChangeManager(
            registry=policies,
            trust_store=trust_store,
            required_approvals=config.policy_approval_quorum,
        )
        service = GovernedService(
            issuer=AuthorizationIssuer(issuer=signer, replay_log=replay_log),
            boundary=ExecutionBoundary(
                replay_log=replay_log,
                trust_store=trust_store,
                policy_registry=policies,
            ),
            policies=policies,
            actions={"write_file": lambda request: request["content"]},
            policy_manager=manager,
        )
        return cls(config, service, signer, replay_log, trust_store, manager)
