import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair
from .engine import ExecutionBoundary
from .issuer import AuthorizationIssuer
from .platform import GovernancePlatform, RuntimeIdentity
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog
from .service import GovernedService
from .storage import PostgresReplayLog, PostgresTrustStore
from .signing import Signer
from .identity import OIDCValidator, UrlJWKSProvider
from .trust import TrustStore


def build_demo_service(
    *,
    mesh_source_registry=None,
) -> tuple[GovernedService, KeyPair, ReplayLog]:
    """Build a complete in-process composition for demos and integration tests."""
    issuer = KeyPair.generate("demo-issuer")
    replay_log = ReplayLog()
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy_registry = PolicyRegistry(
        (
            Policy(
                "demo-files-v1",
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            ),
        )
    )
    service = GovernedService(
        issuer=AuthorizationIssuer(
            issuer=issuer,
            replay_log=replay_log,
            mesh_source_registry=mesh_source_registry,
        ),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=policy_registry,
        ),
        policies=policy_registry,
        actions={"write_file": lambda request: request["content"]},
        mesh_source_registry=mesh_source_registry,
    )
    return service, issuer, replay_log


def build_runtime_service(
    *,
    signer: Signer | None = None,
) -> tuple[GovernedService, Signer, ReplayLog]:
    """Build the server composition from explicit production environment settings.

    A deployment may inject a remote or KMS-backed signer. When omitted, the
    legacy environment-backed local key path remains available for development
    and controlled deployments.
    """
    mode = os.environ.get("GAS_RUNTIME_MODE", "postgres").lower()
    if mode == "memory":
        return build_demo_service()
    if mode != "postgres":
        raise ValueError("GAS_RUNTIME_MODE must be postgres or memory")

    database_url = os.environ.get("DATABASE_URL")
    key_id = os.environ.get("GAS_ISSUER_KEY_ID")
    private_key = os.environ.get("GAS_ISSUER_PRIVATE_KEY")
    if not database_url or signer is None and not all((key_id, private_key)):
        raise RuntimeError(
            "DATABASE_URL and either an injected signer or "
            "GAS_ISSUER_KEY_ID/GAS_ISSUER_PRIVATE_KEY are required in postgres runtime mode"
        )
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("install the postgres extra to use postgres runtime mode") from exc

    issuer = signer or KeyPair.from_private_key_b64(key_id, private_key)
    replay_log = PostgresReplayLog(psycopg.connect(database_url))
    trust_store = PostgresTrustStore(replay_log.connection)
    if trust_store.resolve(issuer.key_id) is None:
        trust_store.add(
            issuer.key_id,
            Ed25519PublicKey.from_public_bytes(issuer.public_key_bytes()),
        )
    policy_registry = PolicyRegistry(
        (
            Policy(
                "demo-files-v1",
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            ),
        )
    )
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=replay_log),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=policy_registry,
        ),
        policies=policy_registry,
        actions={"write_file": lambda request: request["content"]},
    )
    return service, issuer, replay_log


def build_runtime_service_with_oidc(
    *,
    signer: Signer | None = None,
) -> tuple[GovernedService, Signer, ReplayLog, OIDCValidator | None]:
    """Build the runtime composition and, when OIDC environment variables are
    present, construct an OIDCValidator and return it as the fourth tuple
    element. This helper preserves the original API of build_runtime_service
    while enabling deployments to opt-in to environment-configured OIDC.
    """
    service, issuer, replay_log = build_runtime_service(signer=signer)
    oidc_issuer = os.environ.get("OIDC_ISSUER")
    oidc_audience = os.environ.get("OIDC_AUDIENCE")
    oidc_jwks_url = os.environ.get("OIDC_JWKS_URL")
    if any((oidc_issuer, oidc_audience, oidc_jwks_url)) and not all(
        (oidc_issuer, oidc_audience, oidc_jwks_url)
    ):
        raise RuntimeError("OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL must be configured together")
    oidc_validator = None
    if oidc_issuer and oidc_audience and oidc_jwks_url:
        oidc_validator = OIDCValidator(
            issuer=oidc_issuer,
            audience=oidc_audience,
            jwks_provider=UrlJWKSProvider(oidc_jwks_url),
        )
    return service, issuer, replay_log, oidc_validator


def build_platform_demo(
    *,
    service_name: str = "governed-file-api",
    environment: str = "prod",
    tenant_id: str | None = None,
    actor_id: str | None = None,
    mesh_source_registry=None,
) -> tuple[GovernancePlatform, GovernedService, KeyPair, ReplayLog]:
    """Build a platform-ready composition with runtime identity and runtime metadata."""
    service, issuer, replay_log = build_demo_service(mesh_source_registry=mesh_source_registry)
    platform = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(
            service=service_name,
            environment=environment,
            tenant_id=tenant_id,
            actor_id=actor_id,
        ),
        mesh_source_registry=mesh_source_registry,
    )
    return platform, service, issuer, replay_log
