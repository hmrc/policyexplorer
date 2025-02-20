from dataclasses import dataclass
from typing import Any, Dict, List

from policyexplorer.common import ensure_array, matches_pattern
from policyexplorer.request_context import RequestContext


@dataclass
class ConditionItem:
    operator: str
    key: str
    value: List[str] | bool

    def is_operator_negated(self) -> bool:
        return "Not" in self.operator

    # def has_set_operator(self) -> bool:
    #     return "ForAllValues:" in self.operator or "ForAnyValue:" in self.operator

    def evaluate(self, request_context: RequestContext) -> bool:
        # Currently, only supports single-valued context key evaluation
        #
        # ToDo: consider ForAnyValue and ForAllValue qualifiers, as well as IfExists

        request_context_item = request_context.get_item_by_key(self.key)

        if not request_context_item:
            return False

        if isinstance(self.value, bool):
            result = self.value == request_context_item.value
        else:
            result = any([matches_pattern(pattern=v, string=request_context_item.value) for v in self.value])

        # breakpoint()

        if self.is_operator_negated():
            return not result

        return result


class Condition:

    def __init__(self, condition: Dict[str, Any]) -> None:
        self._condition = condition
        self.items = self._items()

    def _items(self) -> List[ConditionItem]:
        items = []
        for operator, context in self._condition.items():
            for k, v in context.items():
                value = v
                if not isinstance(v, bool):
                    value = ensure_array(v)
                items.append(ConditionItem(operator=operator, key=k, value=value))
        return items

    def evaluate(self, request_context: RequestContext) -> bool:
        return all([condition_item.evaluate(request_context=request_context) for condition_item in self.items])


    # based on the evaluate() return value how do you determine whos allowed? consider negated conditions