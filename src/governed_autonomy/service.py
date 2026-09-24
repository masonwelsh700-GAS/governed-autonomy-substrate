from collections.abc import Callable, Sequence
from typing import Any

from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .health import health_report
from .issuer import AuthorizationIssuer
from .mesh import GovernanceInput, GovernanceSourceRegistry
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .platform_admin import PolicyChangeManager
from .policy import Policy, PolicyRegistry


class GovernedService:
    """Application facade that binds authorized action names to safe handlers."""

    def __init__(self, *, issuer: AuthorizationIssuer, boundary: ExecutionBoundary,
                 policies: PolicyRegistry | dict[str, Policy],
                 actions: dict[str, Callable[[dict[str, Any]], Any]],
                 mesh_source_registry: GovernanceSourceRegistry | None = None,
                 policy_manager: PolicyChangeManager | None = None) -> None:
        self.issuer = issuer
        self.boundary = boundary
        self.mesh_source_registry = mesh_source_registry
        self.policy_manager = policy_manager
        self.policies = policies if isinstance(policies, PolicyRegistry) else PolicyRegistry(tuple(policies.values()))
        self.actions = dict(actions)

    def authorize(self, request: dict[str, Any], policy_id: str, *, ttl_seconds: int = 300,
                  approvals: Sequence[SignedApproval | dict[str, Any]] | None = None,
                  mesh_inputs: Sequence[GovernanceInput] | None = None) -> GovernanceAuthorizationArtifact:
        policy = self.policies.get(policy_id)
        if policy is None:
            raise AuthorizationError(f"unknown policy: {policy_id}")
        if self.mesh_source_registry is not None and self.issuer.mesh_source_registry is None:
            self.issuer.mesh_source_registry = self.mesh_source_registry
        return self.issuer.authorize(request, policy, ttl_seconds=ttl_seconds,
                                     approvals=approvals, mesh_inputs=mesh_inputs)

    def execute(self, artifact: GovernanceAuthorizationArtifact) -> Any:
        action = self.actions.get(artifact.action_request.get("action"))
        if action is None:
            raise AuthorizationError(f"unknown executable action: {artifact.action_request.get('action')}")
        return self.boundary.execute(artifact, action)

    def execute_dict(self, value: dict[str, Any]) -> Any:
        return self.execute(GovernanceAuthorizationArtifact.from_dict(value))

    def execute_json(self, value: str) -> Any:
        return self.execute(GovernanceAuthorizationArtifact.from_json(value))

    def audit_report(self) -> dict[str, Any]:
        return {"actions": sorted(self.actions), "policy_ids": sorted(self.policies.versions()),
                "policy_digests": self.policies.digests(),
                "audit_summary": self.boundary.replay_log.audit_summary(),
                "health": health_report(replay_log=self.boundary.replay_log,
                                         trust_store=self.boundary.trust_store,
                                         policy_registry=self.policies,
                                         mesh_source_registry=self.mesh_source_registry)}
