from dataclasses import dataclass
from typing import Dict, List


@dataclass
class RequestContextItem:
    key: str
    value: bool | str | List[str]


@dataclass
class RequestContext:
    items: Dict[str, RequestContextItem]

    def get_item_by_key(self, key: str) -> RequestContextItem | None:
        return self.items.get(key, None)
