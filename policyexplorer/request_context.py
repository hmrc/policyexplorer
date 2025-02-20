
from dataclasses import dataclass
from typing import Dict


@dataclass
class RequestContextItem:
    key: str
    value: str # extend with List[str] to support multivalued context key values


@dataclass
class RequestContext:
    items: Dict[str, RequestContextItem]

    def get_item_by_key(self, key: str) -> RequestContextItem | None:
        return self.items.get(key, None)

