"""Deployment identity for single-customer data planes.

The context is deployment configuration, never a value accepted from events or
API request bodies. It identifies the scope of a local data store; it does not
by itself prove network, host, cloud-region, or cryptographic isolation.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Mapping
from uuid import UUID


_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTEXT_VARIABLES = (
    "BK_SECURITY_CUSTOMER_REF",
    "BK_SECURITY_DEPLOYMENT_ID",
    "BK_SECURITY_REGION",
)


@dataclass(frozen=True, slots=True)
class DeploymentContext:
    profile: str = "local_v1"
    customer_ref: str | None = None
    deployment_id: str | None = None
    region: str | None = None

    def __post_init__(self) -> None:
        if self.profile == "local_v1":
            if any(value is not None for value in (self.customer_ref, self.deployment_id, self.region)):
                raise ValueError("Local V1 deployment cannot carry dedicated data-plane identifiers.")
            return
        if self.profile != "dedicated_customer":
            raise ValueError("Deployment profile must be local_v1 or dedicated_customer.")
        if not isinstance(self.customer_ref, str) or not _SLUG.fullmatch(self.customer_ref):
            raise ValueError("Dedicated data plane requires an opaque lowercase customer reference.")
        if not isinstance(self.region, str) or not _SLUG.fullmatch(self.region):
            raise ValueError("Dedicated data plane requires a configured region identifier.")
        try:
            normalized_id = str(UUID(str(self.deployment_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Dedicated data plane requires a UUID deployment identifier.") from exc
        object.__setattr__(self, "deployment_id", normalized_id)

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> "DeploymentContext":
        profile = str(env.get("BK_SECURITY_DEPLOYMENT_PROFILE", "local_v1")).strip().lower()
        if profile == "local_v1":
            if any(str(env.get(name, "")).strip() for name in _CONTEXT_VARIABLES):
                raise ValueError("Dedicated deployment identifiers require BK_SECURITY_DEPLOYMENT_PROFILE=dedicated_customer.")
            return cls()
        if profile != "dedicated_customer":
            raise ValueError("BK_SECURITY_DEPLOYMENT_PROFILE must be local_v1 or dedicated_customer.")
        missing = [name for name in _CONTEXT_VARIABLES if not str(env.get(name, "")).strip()]
        if missing:
            raise ValueError("Dedicated data plane is missing required identity settings: " + ", ".join(missing))
        return cls(
            profile=profile,
            customer_ref=str(env["BK_SECURITY_CUSTOMER_REF"]).strip(),
            deployment_id=str(env["BK_SECURITY_DEPLOYMENT_ID"]).strip(),
            region=str(env["BK_SECURITY_REGION"]).strip().lower(),
        )

    def database_binding(self) -> tuple[str, str, str, str]:
        if self.profile != "dedicated_customer":
            raise ValueError("Only a dedicated customer deployment can bind a customer database.")
        return (self.profile, str(self.customer_ref), str(self.deployment_id), str(self.region))

    def reporting_scope(self) -> dict[str, str | None]:
        if self.profile == "dedicated_customer":
            return {
                "profile": self.profile,
                "customer_ref": self.customer_ref,
                "region": self.region,
                "region_attestation": "not_verified",
                "scope_enforcement": "database_startup_binding_only",
            }
        return {
            "profile": "local_v1",
            "customer_ref": None,
            "region": None,
            "region_attestation": "not_applicable",
            "scope_enforcement": "single_local_instance",
        }
