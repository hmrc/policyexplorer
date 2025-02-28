from typing import Any, Dict, List

from policyexplorer.common import ensure_array
from policyexplorer.condition import Condition
from policyexplorer.effect import Effect
from policyexplorer.exception import StatmentElementNotFoundException
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
        self.not_action = self._not_action()
        self.resource = self._resource()
        self.condition = self._condition()
        self._validate()
        self.permission_table = self._permission_table()

    def _effect(self) -> str:
        return str(self._statement["Effect"])

    def _principal(self) -> List[Principal]:
        principal_raw = self._statement["Principal"]
        if isinstance(principal_raw, dict):
            # Intentionally overlooking the type of principal
            principals = [
                Principal(identifier=p, excludes=[], only=[])
                for _, values in principal_raw.items()
                for p in ensure_array(values)
            ]
        else:
            principals = [Principal(identifier=principal_raw, excludes=[], only=[])]
        return principals

    def _action(self) -> List[str]:
        return ensure_array(self._statement.get("Action", []))

    def _not_action(self) -> List[str]:
        if self._statement.get("Action"):
            return []
        return ensure_array(self._statement.get("NotAction", []))

    def _resource(self) -> List[str]:
        return ensure_array(self._statement["Resource"])

    def _condition(self) -> Condition:
        return Condition(raw=self._statement.get("Condition", {}))

    def _validate(self) -> None:
        if len(self.action) == 0 and len(self.not_action) == 0:
            raise StatmentElementNotFoundException("Statement must include either an Action or NotAction element")

    # TODO:
    # Consider other elements of IAM Policy statement:
    #   * NotPrincipal
    #   * NotResource

    def _permission_table(self) -> PermissionTable:
        table: Dict[Principal, Dict[str, PermissionEffect]] = {}

        _principals = []

        _effect = PermissionEffect[self.effect.upper()]
        if self.not_action:
            _effect = PermissionEffect[self.effect.upper()].invert

        _actions = self.action
        if self.not_action:
            _actions = self.not_action

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

            for a in _actions:
                for r in self.resource:
                    action_resource_key = f"{a}-{r}"
                    table[p][action_resource_key] = _effect
                    if self.condition:
                        for condition_item in self.condition.items:
                            for cp in condition_item.get_principals():
                                if not table.get(cp):
                                    table[cp] = {}
                                if condition_item.is_operator_negated():
                                    table[cp][action_resource_key] = _effect.invert
                                else:
                                    table[cp][action_resource_key] = _effect

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
