"""
IAM telemetry collector.

Enumerates users, roles, policies, and access key metadata using read-only
IAM APIs. Produces normalized records for downstream security posture analysis
and detection validation.

Permissions required (read-only):
    iam:ListUsers
    iam:ListUserPolicies
    iam:ListAttachedUserPolicies
    iam:ListGroupsForUser
    iam:ListAccessKeys
    iam:GetAccessKeyLastUsed
    iam:ListMFADevices
    iam:ListRoles
    iam:ListRolePolicies
    iam:ListAttachedRolePolicies
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

import structlog
from botocore.exceptions import ClientError

from .base_collector import BaseCollector
from .schema import IAMAccessKey, IAMRole, IAMUser

logger = structlog.get_logger(__name__)


class IAMCollector(BaseCollector):
    """
    Collect IAM users, roles, and access key metadata.

    Yields a mix of IAMUser, IAMRole, and IAMAccessKey objects.  Callers
    can filter by type to process each category independently.
    """

    @property
    def collector_name(self) -> str:
        return "iam"

    def collect(self) -> Iterator[IAMUser | IAMRole | IAMAccessKey]:
        """Yield IAMUser, IAMRole, and IAMAccessKey normalized records."""
        iam = self._session.client("iam")

        yield from self._collect_users(iam)
        yield from self._collect_roles(iam)

    # ──────────────────────────────────────────────────────────────────
    # Users
    # ──────────────────────────────────────────────────────────────────

    def _collect_users(self, iam: object) -> Iterator[IAMUser | IAMAccessKey]:
        paginator = iam.get_paginator("list_users")
        try:
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]

                    mfa_active = self._has_mfa(iam, user_name)
                    attached_policies = self._list_attached_user_policies(iam, user_name)
                    inline_policies = self._list_inline_user_policies(iam, user_name)
                    groups = self._list_user_groups(iam, user_name)
                    access_keys = list(self._collect_access_keys(iam, user_name))

                    password_last_used: datetime | None = user.get("PasswordLastUsed")

                    yield IAMUser(
                        user_id=user["UserId"],
                        user_name=user_name,
                        arn=user["Arn"],
                        created=user["CreateDate"],
                        password_last_used=password_last_used,
                        mfa_active=mfa_active,
                        access_keys=access_keys,
                        attached_policies=attached_policies,
                        inline_policy_names=inline_policies,
                        groups=groups,
                    )

                    yield from access_keys

        except ClientError as exc:
            self._log.error("iam_list_users_failed", error=str(exc))
            raise

    def _collect_access_keys(
        self, iam: object, user_name: str
    ) -> Iterator[IAMAccessKey]:
        try:
            paginator = iam.get_paginator("list_access_keys")
            for page in paginator.paginate(UserName=user_name):
                for key in page.get("AccessKeyMetadata", []):
                    last_used_data = self._get_key_last_used(
                        iam, key["AccessKeyId"]
                    )
                    yield IAMAccessKey(
                        access_key_id=key["AccessKeyId"],
                        user_name=user_name,
                        status=key["Status"],
                        created=key["CreateDate"],
                        last_used=last_used_data.get("LastUsedDate"),
                        last_used_region=last_used_data.get("Region"),
                        last_used_service=last_used_data.get("ServiceName"),
                    )
        except ClientError as exc:
            self._log.warning(
                "iam_list_access_keys_failed", user=user_name, error=str(exc)
            )

    def _get_key_last_used(self, iam: object, key_id: str) -> dict:
        try:
            response = iam.get_access_key_last_used(AccessKeyId=key_id)
            return response.get("AccessKeyLastUsed", {})
        except ClientError:
            return {}

    def _has_mfa(self, iam: object, user_name: str) -> bool:
        try:
            response = iam.list_mfa_devices(UserName=user_name)
            return len(response.get("MFADevices", [])) > 0
        except ClientError:
            return False

    def _list_attached_user_policies(self, iam: object, user_name: str) -> list[str]:
        try:
            paginator = iam.get_paginator("list_attached_user_policies")
            arns: list[str] = []
            for page in paginator.paginate(UserName=user_name):
                arns.extend(p["PolicyArn"] for p in page.get("AttachedPolicies", []))
            return arns
        except ClientError:
            return []

    def _list_inline_user_policies(self, iam: object, user_name: str) -> list[str]:
        try:
            paginator = iam.get_paginator("list_user_policies")
            names: list[str] = []
            for page in paginator.paginate(UserName=user_name):
                names.extend(page.get("PolicyNames", []))
            return names
        except ClientError:
            return []

    def _list_user_groups(self, iam: object, user_name: str) -> list[str]:
        try:
            paginator = iam.get_paginator("list_groups_for_user")
            groups: list[str] = []
            for page in paginator.paginate(UserName=user_name):
                groups.extend(g["GroupName"] for g in page.get("Groups", []))
            return groups
        except ClientError:
            return []

    # ──────────────────────────────────────────────────────────────────
    # Roles
    # ──────────────────────────────────────────────────────────────────

    def _collect_roles(self, iam: object) -> Iterator[IAMRole]:
        paginator = iam.get_paginator("list_roles")
        try:
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    attached = self._list_attached_role_policies(iam, role_name)
                    inline = self._list_inline_role_policies(iam, role_name)
                    yield IAMRole(
                        role_id=role["RoleId"],
                        role_name=role_name,
                        arn=role["Arn"],
                        created=role["CreateDate"],
                        assume_role_policy=role.get("AssumeRolePolicyDocument", {}),
                        attached_policies=attached,
                        inline_policy_names=inline,
                    )
        except ClientError as exc:
            self._log.error("iam_list_roles_failed", error=str(exc))
            raise

    def _list_attached_role_policies(self, iam: object, role_name: str) -> list[str]:
        try:
            paginator = iam.get_paginator("list_attached_role_policies")
            arns: list[str] = []
            for page in paginator.paginate(RoleName=role_name):
                arns.extend(p["PolicyArn"] for p in page.get("AttachedPolicies", []))
            return arns
        except ClientError:
            return []

    def _list_inline_role_policies(self, iam: object, role_name: str) -> list[str]:
        try:
            paginator = iam.get_paginator("list_role_policies")
            names: list[str] = []
            for page in paginator.paginate(RoleName=role_name):
                names.extend(page.get("PolicyNames", []))
            return names
        except ClientError:
            return []
