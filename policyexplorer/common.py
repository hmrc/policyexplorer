import re
from typing import List


def ensure_array(element: str|List[str]) -> List[str]:
    if isinstance(element, list):
        return element
    else:
        return [element]


def pattern_to_regex(wildcard: str) -> str:
    # need to handle "?" too esp when there are more than 1 "?"
    return ".*".join(wildcard.split("*")) + "$"

def matches_pattern(pattern: str, string: str) -> bool:
    # *, P1 = True
    # P*, P1 = True
    # P*X, P1 = False
    # P*X, P1X = True
    # P*X, P1XA = False
    # P*X*, P1XA = True

    return re.search(pattern_to_regex(pattern), string) is not None
