import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair
from .engine import ExecutionBoundary
from .issuer import AuthorizationIssuer
from .platform import GovernancePlatform, RuntimeIdentity
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog
from .runtime import ProductionRuntime, RuntimeConfig
from .service import GovernedService
from .storage import PostgresReplayLog, PostgresTrustStore
from .signing import Signer
from .trust import TrustStore


def build_demo_service(*, mesh_source_registry=None) -> tuple[GovernedService, KeyPair, ReplayLog]:
    """Build a complete in-process composition for demos and integration tests."""
    issuer = KeyPair.generate("demo-issuer")
    replay_log = ReplayLog()
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy_registry = PolicyRegistry((Policy("demo-files-v1", ("write_file",),
        {"write_file": ("path", "content")}, {"write_file": {"path": "out.txt"}}),))
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=replay_log,
                                    mesh_source_registry=mesh_source_registry),
        boundary=ExecutionBoundary(replay_log=replay_log, trust_store=trust_store,
                                   policy_registry=policy_registry),
        policies=policy_registry, actions={"write_file": lambda request: request["content"]},
        mesh_source_registry=mesh_source_registry,
    )
    return service, issuer, replay_log


def build_runtime_service(*, signer: Signer | None = None) -> tuple[GovernedService, Signer, ReplayLog]:
    """Build the runtime from validated environment settings."""
    config = RuntimeConfig.from_env()
    if config.mode == "memory":
        return build_demo_service()
    runtime = ProductionRuntime.create(config=config, signer=signer)
    return runtime.service, runtime.signer, runtime.replay_log


def build_platform_demo(*, service_name: str = "governed-file-api", environment: str = "prod",
                        tenant_id: str | None = None, actor_id: str | None = None,
                        mesh_source_registry=None) -> tuple[GovernancePlatform, GovernedService, KeyPair, ReplayLog]:
    """Build a platform-ready composition with runtime identity and metadata."""
    service, issuer, replay_log = build_demo_service(mesh_source_registry=mesh_source_registry)
    platform = GovernancePlatform(service=service, identity=RuntimeIdentity(
        service=service_name, environment=environment, tenant_id=tenant_id, actor_id=actor_id),
        mesh_source_registry=mesh_source_registry)
    return platform, service, issuer, replay_log
