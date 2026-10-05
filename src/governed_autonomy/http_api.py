from .admin_ui import render_admin_css, render_admin_js, render_admin_ui
from .bootstrap import build_runtime_service
from .deployment import BoundedRateLimiter, TLSConfig, security_headers
from .errors import AuthorizationError
from .health import health_report
from .identity import (
    EntraOIDCConfig,
    ExternalIdentity,
    IdentityValidationError,
    OIDCAuthCodeClient,
    OIDCValidator,
    UrlJWKSProvider,
    discover_oidc_configuration,
    entra_oidc_validator_from_discovery,
    oidc_validator_from_discovery,
)
from .issuer import PolicyDeniedError
from .jobs import JobStoreError, JobSubmissionStore, SQLiteJobStore
from .logging_config import configure_logging
from .mesh import GovernanceInput
from .operator_auth import OperatorKeyStore
from .platform import RuntimeIdentity
from .platform_admin import PolicyChangeManager, TrustChangeManager
from .policy import policy_from_dict
from .rbac import Role
from .service import GovernedService

API_VERSION = "1"
_versioned_get = frozenset(
    {"/health", "/livez", "/readyz", "/startupz", "/audit", "/openapi.json"}
)
