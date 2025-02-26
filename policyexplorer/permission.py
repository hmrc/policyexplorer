from enum import StrEnum
from typing import Dict


class PermissionEffect(StrEnum):
    ALLOW = "Allow"
    DENY = "ExplicitDeny"
    IMPLICIT_DENY = "ImplicitDeny"

    def __init__(self, effect: str):
        self.effect = effect

    @property
    def invert(self) -> "PermissionEffect":
        return {
            PermissionEffect.ALLOW: PermissionEffect.IMPLICIT_DENY,
            PermissionEffect.DENY: PermissionEffect.IMPLICIT_DENY,
        }[self.effect]

    @staticmethod
    def precedence() -> Dict[int, str]:
        return {
            PermissionEffect.IMPLICIT_DENY: 0,
            PermissionEffect.ALLOW: 1,
            PermissionEffect.DENY: 2,
        }

    def __gt__(self, other: "PermissionEffect") -> bool:
        precedence = self.precedence()

        if precedence[self] > precedence[other]:
            return True
        return False

    def __lt__(self, other: "PermissionEffect") -> bool:
        precedence = self.precedence()

        if precedence[self] < precedence[other]:
            return True
        return False
