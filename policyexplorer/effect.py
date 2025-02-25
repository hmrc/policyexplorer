from enum import StrEnum


class Effect(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"

    def __init__(self, effect: str):
        self.effect = effect

    @property
    def invert(self) -> str:
        return {
            "Allow": "Deny",
            "Deny": "Allow"
        }[self.effect]