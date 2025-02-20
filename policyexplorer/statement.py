from enum import StrEnum
from typing import Any, Dict

from policyexplorer.common import ensure_array, matches_pattern
from policyexplorer.condition import Condition
from policyexplorer.exception import RequestContextItemNotFoundException
from policyexplorer.request_context import RequestContext

class Effect(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"

class Statement:

    def __init__(self, statement: Dict[str, Any]) -> None:
        self._statement = statement
        self.effect = self._effect()
        self.principal = self._principal()
        self.action = self._action()
        self.resource = self._resource()
        self.condition = self._condition()
        self._statement_table = self.statement_table()

    def _effect(self) -> str:
        return self._statement.get("Effect")

    def _principal(self) -> str:
        return ensure_array(self._statement.get("Principal"))

    def _action(self) -> str:
        return ensure_array(self._statement.get("Action"))

    def _resource(self) -> str:
        return ensure_array(self._statement.get("Resource"))

    def _condition(self) -> Condition:
        return Condition(condition=self._statement.get("Condition", {}))

    # consider other elements of IAM Policy statement:
    #   * NotPrincipal
    #   * NotAction
    #   * NotResource


    def statement_table(self) -> Dict[str, Any]:
        # Given a statement:
        # dict(
        #     Effect="Allow",
        #     Principal=["P1", "P2"],
        #     Action=["A1", "A2"],
        #     Resource=["R1", "R2"],
        # )
        #
        # Graph: No of paths = len(Principal) x len(Action) x len(Resource) => with special rule for wildcards
        #   P1-A1-R1
        #   P1-A2-R1
        #   P1-A1-R2
        #   P1-A2-R2
        #   P2-A1-R1
        #   P2-A2-R1
        #   P2-A1-R2
        #   P2-A2-R2
        
        # How do you compare an ARN against a wildcard ARN?

        # table = {
        #     "P1": {
        #         "A1-R1": "R1",
        #         "A1-R2": "R2",
        #         "A2-R1": "R1",
        #         "A2-R2": "R2",
        #     },
        #     "P2": {
        #         "A1-R1": "R1",
        #         "A1-R2": "R2",
        #         "A2-R1": "R1",
        #         "A2-R2": "R2",
        #     },
        # }

        table = {}

        for p in self.principal:
            if not table.get(p):
                table[p] = {}
            
            for a in self.action:
                for r in self.resource:
                    action_resource_key = f"{a}-{r}"
                    table[p][action_resource_key] = r

        return table

    # build statement_table
    # is_matched_by_statement_table(rc) ==> principal, action, resource
    # is_matched_by_condition(rc)

    def is_matched_by_statement_table(self, request_context: RequestContext) -> bool:

        # Assumption: the following request context keys are assumed

        principal = request_context.get_item_by_key("aws:PrincipalArn") # Consider service ARN too?
        if not principal:
            raise RequestContextItemNotFoundException("request context item not found - aws:PrincipalArn")

        action = request_context.get_item_by_key("Action")
        if not action:
            raise RequestContextItemNotFoundException("request context item not found - Action")

        resource = request_context.get_item_by_key("Resource")
        if not resource:
            raise RequestContextItemNotFoundException("request context item not found - Resource")


        action_resource_key = f"{action.value}-{resource.value}"

        for pk in self._statement_table.keys():
            if matches_pattern(pattern=pk, string=principal.value):
                for ark in self._statement_table[pk].keys():
                    if matches_pattern(pattern=ark, string=action_resource_key):
                        return True

        return False

    def is_matched_by_condition(self, request_context: RequestContext) -> bool:
        return self.condition.evaluate(request_context=request_context)

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
            if self.is_matched_by_statement_table(request_context=request_context) and self.is_matched_by_condition(request_context=request_context):
                result = Effect.ALLOW

        if self.effect == Effect.DENY:
            if self.is_matched_by_statement_table(request_context=request_context) and not self.is_matched_by_condition(request_context=request_context):
                result = Effect.ALLOW

        return result
