import re
from typing import List


def ensure_array(element: str | List[str]) -> List[str]:
    if isinstance(element, list):
        return element
    else:
        return [element]


def pattern_to_regex(wildcard: str) -> str:
    # TODO: need to handle "?" too esp when there are more than 1 "?"
    return ".*".join(wildcard.split("*")) + "$"


def matches_pattern(pattern: str, string: str) -> bool:
    return re.fullmatch(pattern_to_regex(pattern), string) is not None
