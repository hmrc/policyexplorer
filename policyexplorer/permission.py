from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Dict


@dataclass
class Permission:
    action: str
    resource: str

    def __hash__(self) -> int:
        return hash((self.action, self.resource))

    @staticmethod
    def from_string(permission_string: str) -> "Permission":
        action, resource = "", ""
        match = re.match("(.*:.*)-(.*)", permission_string)
        if match:
            action, resource = match.groups()
        return Permission(action=action, resource=resource)


class PermissionEffect(StrEnum):
    ALLOW = "Allow"
    DENY = "ExplicitDeny"
    IMPLICIT_DENY = "ImplicitDeny"

    def __init__(self, effect: "PermissionEffect"):
        self.effect = effect

    @property
    def invert(self) -> "PermissionEffect":
        return {
            PermissionEffect.IMPLICIT_DENY: PermissionEffect.IMPLICIT_DENY,
            PermissionEffect.ALLOW: PermissionEffect.IMPLICIT_DENY,
            PermissionEffect.DENY: PermissionEffect.IMPLICIT_DENY,
        }[self.effect]

    @staticmethod
    def precedence() -> Dict["PermissionEffect", int]:
        return {
            PermissionEffect.IMPLICIT_DENY: 0,
            PermissionEffect.ALLOW: 1,
            PermissionEffect.DENY: 2,
        }

    def __gt__(self, other: "PermissionEffect") -> bool:  # type: ignore[override]
        precedence = self.precedence()
        if precedence[self] > precedence[other]:
            return True
        return False

    def __lt__(self, other: "PermissionEffect") -> bool:  # type: ignore[override]
        precedence = self.precedence()
        if precedence[self] < precedence[other]:
            return True
        return False
