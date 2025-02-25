from dataclasses import dataclass
import re
from typing import Any, Dict, List

from policyexplorer.common import matches_pattern
from policyexplorer.exception import RequestContextItemNotFoundException
from policyexplorer.permission import PermissionEffect
from policyexplorer.principal import Principal
from policyexplorer.request_context import RequestContext


@dataclass
class PermissionTable:
    table: Dict[Principal, Dict[str, PermissionEffect]]

    def __eq__(self, other: "PermissionTable") -> bool:
        """Overrides the default implementation"""
        if isinstance(other, PermissionTable):
            l = [other.table.get(k) and other.table.get(k) == v for k, v in self.table.items()]
            return len(l) > 0 and all(l)
        return False


    def merge(self, other: "PermissionTable") -> None:
        for pk, value in other.table.items():
            if self.table.get(pk):
                for action_resource_key, effect in value.items():
                    this_table_item = self.table[pk]
                    if not this_table_item.get(action_resource_key):
                        this_table_item[action_resource_key] = effect
                    else:
                        # Ensure effective permission is set based on the following precedence [(ImplicityDeny, 0), (Allow, 1), (Deny, 2)]
                        if effect > this_table_item[action_resource_key]:
                            this_table_item[action_resource_key] = effect
            else:
                self.table[pk] = value

    @staticmethod
    def has_wildcard(string: str) -> bool:
        wildcard_characters = ["*", "?"]
        return any([wc in string for wc in wildcard_characters])

    def is_principal_allowed_action(self, principal: Principal, action: str, resource: str = "*") -> bool:
        permissions = []
        action_resource = f"{action}-{resource}"

        for key, value in self.table.items():
            if key.match(subject=principal):
                for ark, effect in value.items():
                    _action, _resource = re.match("(.*:.*)-(.*)", ark).groups()

                    if not self.has_wildcard(string=_resource):
                        new_ark = f"{_action}-{resource}"
                    else:
                        new_ark = ark

                    if matches_pattern(pattern=new_ark, string=action_resource):
                        permissions.append(effect)

        return len(permissions) > 0 and PermissionEffect.ALLOW in permissions and PermissionEffect.DENY not in permissions

    def match(self, request_context: RequestContext) -> bool:
        # Note: [Assumption] The following request context keys are assumed
        print(f"\n\n{ self.table = }")

        _principal = request_context.get_item_by_key("aws:PrincipalArn") # Consider service ARN too?
        if not _principal:
            raise RequestContextItemNotFoundException("request context item not found - aws:PrincipalArn")
        principal = Principal(_principal.value, [], [])

        action = request_context.get_item_by_key("Action")
        if not action:
            raise RequestContextItemNotFoundException("request context item not found - Action")

        resource = request_context.get_item_by_key("Resource")
        if not resource:
            raise RequestContextItemNotFoundException("request context item not found - Resource")


        action_resource_key = f"{action.value}-{resource.value}"

        for pk in self.table.keys():
            if pk.match(subject=principal):
                for ark in self.table[pk].keys():
                    if matches_pattern(pattern=ark, string=action_resource_key):
                        return True

        return False