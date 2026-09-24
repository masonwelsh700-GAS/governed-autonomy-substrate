# Signing-key lifecycle

The runtime uses a fail-closed, monotonic state machine. Every state change must be
anchored as an administrative replay event by the caller that owns the lifecycle.

```text
Generated ──activate──> Active ──begin rotation──> Rolling ──grace window──> Grace ──retire──> Archived
    │                       │                         │                         │
    └──── emergency revoke ─┴──── emergency revoke ───┴──── emergency revoke ───┴── revoke ──> Revoked ──archive──> Archived
```

## States

- **Generated**: metadata exists, but the key cannot sign production GAAs.
- **Active**: the signer is trusted for new GAAs; only one active issuer is expected per runtime.
- **Rolling**: a successor is being introduced; new issuance should move to the successor.
- **Grace**: the old key may verify already-issued, unexpired GAAs until `graceUntil`.
- **Revoked**: verification and new issuance are immediately rejected.
- **Archived**: retained for historical evidence only; never accepted for verification.

## Transition rules

- Transitions are explicit and monotonic; no transition returns to `Generated` or `Active`.
- Revocation is allowed from every non-archived state and takes precedence over grace.
- `graceUntil` must be recorded with the transition and must not extend acceptance after revocation.
- A verifier accepts a grace key only when the artifact is otherwise valid, unexpired, and the current time is before `graceUntil`.
- Key lifecycle events should include the key ID, prior/next state, actor, reason, and replay-chain reference.

## Operational controls

Rotation requires the successor public key to be registered before changing the issuer.
Emergency revocation should be the first action during suspected compromise, followed by
reissuing affected authorizations under a new key and investigating the replay evidence.
