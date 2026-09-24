from __future__ import annotations

from dataclasses import dataclass, replace

from .canonical import canonical_json
from .crypto import KeyPair, verify_signature
from .policy import Policy, PolicyRegistry
from .trust import TrustStore


@dataclass(frozen=True)
class PolicyApproval:
    proposal_id: str
    policy_id: str
    policy_digest: str
    approver_key_id: str
    signature: str

    def unsigned_payload(self) -> bytes:
        return canonical_json({
            "proposal_id": self.proposal_id,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "approver_key_id": self.approver_key_id,
        })

    @classmethod
    def issue(cls, *, proposal_id: str, policy_id: str, policy_digest: str,
              approver: KeyPair) -> "PolicyApproval":
        return cls(proposal_id, policy_id, policy_digest, approver.key_id,
                   approver.sign(canonical_json({
                       "proposal_id": proposal_id, "policy_id": policy_id,
                       "policy_digest": policy_digest, "approver_key_id": approver.key_id,
                   })))

    def verify(self, trust_store: TrustStore) -> bool:
        key = trust_store.resolve(self.approver_key_id)
        return key is not None and verify_signature(key, self.unsigned_payload(), self.signature)

    def to_dict(self) -> dict[str, str]:
        return {"proposal_id": self.proposal_id, "policy_id": self.policy_id,
                "policy_digest": self.policy_digest, "approver_key_id": self.approver_key_id,
                "signature": self.signature}


@dataclass(frozen=True)
class PolicyChangeProposal:
    proposal_id: str
    policy_id: str
    current_policy_digest: str
    proposed_policy: Policy
    proposed_by_key_id: str
    rationale: str
    status: str = "pending"
    signature: str = ""
    approvals: tuple[PolicyApproval, ...] = ()

    def unsigned_payload(self) -> bytes:
        return canonical_json({
            "proposal_id": self.proposal_id, "policy_id": self.policy_id,
            "current_policy_digest": self.current_policy_digest,
            "proposed_policy": self.proposed_policy.to_dict(),
            "proposed_by_key_id": self.proposed_by_key_id,
            "rationale": self.rationale, "status": self.status,
        })

    @classmethod
    def propose(cls, *, proposal_id: str, policy: Policy, proposer: KeyPair,
                rationale: str, current_policy_digest: str) -> "PolicyChangeProposal":
        payload = cls(proposal_id, policy.policy_id, current_policy_digest, policy,
                      proposer.key_id, rationale)
        return replace(payload, signature=proposer.sign(payload.unsigned_payload()))

    def verify(self, trust_store: TrustStore) -> bool:
        key = trust_store.resolve(self.proposed_by_key_id)
        return key is not None and verify_signature(key, self.unsigned_payload(), self.signature)

    def approval_count(self) -> int:
        return len({approval.approver_key_id for approval in self.approvals})

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "policy_id": self.policy_id,
            "current_policy_digest": self.current_policy_digest,
            "proposed_policy": self.proposed_policy.to_dict(),
            "proposed_by_key_id": self.proposed_by_key_id,
            "rationale": self.rationale,
            "status": self.status,
            "signature": self.signature,
            "approval_count": self.approval_count(),
            "required_approvals": None,
            "approvals": [approval.to_dict() for approval in self.approvals],
        }


class PolicyChangeManager:
    """Review and activate policy changes with explicit quorum approval."""

    def __init__(self, *, registry: PolicyRegistry, trust_store: TrustStore,
                 required_approvals: int = 2, enforce_separation_of_duties: bool = True,
                 audit_hook=None) -> None:
        if required_approvals <= 0:
            raise ValueError("required_approvals must be positive")
        self.registry = registry
        self.trust_store = trust_store
        self.required_approvals = required_approvals
        self.enforce_separation_of_duties = enforce_separation_of_duties
        self.audit_hook = audit_hook
        self._proposals: dict[str, PolicyChangeProposal] = {}

    def propose(self, *, new_policy: Policy, proposer: KeyPair, rationale: str = "",
                proposal_id: str | None = None) -> PolicyChangeProposal:
        if self.trust_store.resolve(proposer.key_id) is None:
            raise ValueError("proposer key is not trusted")
        existing = self.registry.get(new_policy.policy_id)
        current_digest = existing.digest() if existing is not None else ""
        proposal = PolicyChangeProposal.propose(
            proposal_id=proposal_id or f"policy-proposal:{new_policy.policy_id}:{current_digest or 'new'}",
            policy=new_policy, proposer=proposer, rationale=rationale,
            current_policy_digest=current_digest,
        )
        if not proposal.verify(self.trust_store):
            raise ValueError("proposal signature is invalid")
        self._proposals[proposal.proposal_id] = proposal
        if self.audit_hook:
            self.audit_hook("policy.proposed", proposal.proposal_id)
        return proposal

    def approve(self, proposal_id: str, *, approver: KeyPair) -> PolicyChangeProposal:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown policy proposal: {proposal_id}")
        if proposal.status != "pending":
            raise ValueError("proposal is no longer pending")
        if self.enforce_separation_of_duties and approver.key_id == proposal.proposed_by_key_id:
            raise ValueError("proposer cannot approve the same policy change")
        if self.trust_store.resolve(approver.key_id) is None:
            raise ValueError("approver key is not trusted")
        approval = PolicyApproval.issue(proposal_id=proposal.proposal_id,
                                        policy_id=proposal.policy_id,
                                        policy_digest=proposal.proposed_policy.digest(),
                                        approver=approver)
        if any(item.approver_key_id == approval.approver_key_id for item in proposal.approvals):
            raise ValueError("approver has already voted")
        updated = replace(proposal, approvals=tuple(sorted(
            [*proposal.approvals, approval], key=lambda item: item.approver_key_id)))
        self._proposals[proposal_id] = updated
        if self.audit_hook:
            self.audit_hook("policy.approved", proposal_id)
        return updated

    def activate(self, proposal_id: str) -> Policy:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown policy proposal: {proposal_id}")
        if proposal.status != "pending":
            raise ValueError("proposal is not pending")
        if not proposal.verify(self.trust_store):
            raise ValueError("proposal signature is invalid")
        if proposal.approval_count() < self.required_approvals:
            raise ValueError("approval quorum not met")
        current = self.registry.get(proposal.policy_id)
        if current is not None and current.digest() != proposal.current_policy_digest:
            raise ValueError("policy changed since proposal was created")
        self.registry.register(proposal.proposed_policy)
        self._proposals[proposal_id] = replace(proposal, status="activated")
        if self.audit_hook:
            self.audit_hook("policy.activated", proposal_id)
        return proposal.proposed_policy

    def get(self, proposal_id: str) -> PolicyChangeProposal | None:
        return self._proposals.get(proposal_id)

    def proposals(self) -> tuple[PolicyChangeProposal, ...]:
        return tuple(self._proposals[key] for key in sorted(self._proposals))

    def status(self) -> dict[str, object]:
        pending = [proposal for proposal in self._proposals.values() if proposal.status == "pending"]
        return {"required_approvals": self.required_approvals,
                "pending": len(pending),
                "proposals": [proposal.to_dict() for proposal in self.proposals()]}
