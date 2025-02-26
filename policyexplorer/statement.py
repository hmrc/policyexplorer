from typing import Any, Dict, List

from policyexplorer.common import ensure_array, matches_pattern
from policyexplorer.condition import Condition
from policyexplorer.effect import Effect
from policyexplorer.permission import PermissionEffect
from policyexplorer.permission_table import PermissionTable
from policyexplorer.principal import Principal
from policyexplorer.request_context import RequestContext


class Statement:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self._statement = raw
        self.effect = self._effect()
        self.principal = self._principal()
        self.action = self._action()
        self.resource = self._resource()
        self.condition = self._condition()
        self.permission_table = self._permission_table()

    def _effect(self) -> str:
        return self._statement.get("Effect")

    def _principal(self) -> List[Principal]:
        principals = ensure_array(self._statement.get("Principal"))
        return [Principal(identifier=p, excludes=[], only=[]) for p in principals]

    def _action(self) -> str:
        return ensure_array(self._statement.get("Action"))

    def _resource(self) -> str:
        return ensure_array(self._statement.get("Resource"))

    def _condition(self) -> Condition:
        return Condition(raw=self._statement.get("Condition", {}))

    def _inverse_effect(self) -> str:
        return {
            Effect.ALLOW: Effect.DENY,
            Effect.DENY: Effect.ALLOW,
        }[self.effect]

    # TODO:
    #   Add support for:
    #       * NotAction
    #       * 'Principal: { AWS: "*"}' format
    #   Question: Can 'Principal' field have multiple principal types e.g. AWS, Service?

    # consider other elements of IAM Policy statement:
    #   * NotPrincipal
    #   * NotAction
    #   * NotResource

    def _permission_table(self) -> PermissionTable:
        table = {}

        _principals = []  # From statement Principal element, generate fully formed Principal object (i.e. excludes/only field fully populated) to be used as keys in the table

        for p in self.principal:
            if self.condition:
                for condition_item in self.condition.items:
                    for cp in condition_item.get_principals():
                        # might there be a need to validate if cp is a subset of p?
                        if condition_item.is_operator_negated():
                            p.excludes.append(cp)
                        else:
                            p.only.append(cp)
            _principals.append(p)

        for p in _principals:
            if not table.get(p):
                table[p] = {}

            for a in self.action:
                for r in self.resource:
                    action_resource_key = f"{a}-{r}"
                    table[p][action_resource_key] = PermissionEffect[self.effect.upper()]
                    if self.condition:
                        for condition_item in self.condition.items:
                            for cp in condition_item.get_principals():
                                if not table.get(cp):
                                    table[cp] = {}
                                if condition_item.is_operator_negated():
                                    table[cp][action_resource_key] = PermissionEffect[self.effect.upper()].invert
                                else:
                                    table[cp][action_resource_key] = PermissionEffect[self.effect.upper()]

        return PermissionTable(table=table)

    # Statement Evaluation Grid
    #
    # effect    | is_matched_by_statement_table | is_matched_by_condition | Result
    # ------    | ----------------------------- | ----------------------- | ------
    # 0 (Allow) | 0 (False)                     | 0 (False)               | Deny
    # 0 (Allow) | 0 (False)                     | 1 (True)                | Deny
    # 0 (Allow) | 1 (True)                      | 0 (False)               | Deny
    # 0 (Allow) | 1 (True)                      | 1 (True)                | ALLOW
    # 1 (Deny)  | 0 (False)                     | 0 (False)               | Deny
    # 1 (Deny)  | 0 (False)                     | 1 (True)                | Deny
    # 1 (Deny)  | 1 (True)                      | 0 (False)               | ALLOW
    # 1 (Deny)  | 1 (True)                      | 1 (True)                | Deny

    def evaluate(self, request_context: RequestContext) -> str:
        result = Effect.DENY

        if self.effect == Effect.ALLOW:
            if self.permission_table.match(request_context=request_context) and self.condition.match(
                request_context=request_context
            ):
                result = Effect.ALLOW

        if self.effect == Effect.DENY:
            if self.permission_table.match(request_context=request_context) and not self.condition.match(
                request_context=request_context
            ):
                result = Effect.ALLOW

        return result

    def matches_action(self, action: str) -> bool:
        return any([matches_pattern(pattern=a, string=action) for a in self.action])

    def matches_principal(self, principal: str) -> bool:
        return any([matches_pattern(pattern=p, string=principal) for p in self.principal])
