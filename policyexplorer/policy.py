from typing import Any, Dict, List, Set

from policyexplorer.permission import Permission, PermissionEffect
from policyexplorer.permission_table import PermissionTable
from policyexplorer.principal import Principal
from policyexplorer.statement import Statement


class Policy:
    def __init__(self, raw: Dict[str, Any]):
        self._policy = raw
        self.statement = self._statement()
        self.version = self._version()
        self.permission_table = self._permission_table()

    def _statement(self) -> List[Statement]:
        return [Statement(raw=s) for s in self._policy.get("Statement", [])]

    def _version(self) -> str:
        return self._policy.get("Version", "")

    def _permission_table(self) -> PermissionTable:
        table = PermissionTable(table={})
        for st in self.statement:
            table.merge(other=st.permission_table)
        return table

    # Given an action, get principals that are allowed the action
    def allowed_principals(self, action: str) -> Set[str]:
        return self.allowed_principals_by_resource(action=action, resource="*")

    # Given an action and a resource, get principals that are allowed the action on the resource
    def allowed_principals_by_resource(self, action: str, resource: str) -> List[str]:
        principals = set()
        for principal, _ in self.permission_table.table.items():
            if self.permission_table.is_principal_allowed_action(principal=principal, action=action, resource=resource):
                principals.add(principal)

        return principals

    # Given a principal, determine permissions it has
    def principal_permissions(self, principal: Principal) -> List[Permission]:
        if not self.permission_table.table.get(principal):
            return set()

        return {
            Permission.from_string(action_resource)
            for action_resource, effect in self.permission_table.table[principal]
            if effect == PermissionEffect.ALLOW
        }
