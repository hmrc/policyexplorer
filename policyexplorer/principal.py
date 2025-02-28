from dataclasses import dataclass
from typing import List

from policyexplorer.common import matches_pattern


@dataclass
class Principal:
    identifier: str
    excludes: List["Principal"]  # for principals from negated condition e.g. ArnNotLike
    only: List["Principal"]  # for principals from negated condition e.g ArnLike

    def _stringify(self, principals: List["Principal"]) -> str:
        return "-".join([p.identifier for p in principals])

    def __hash__(self) -> int:
        return hash((self.identifier, self._stringify(self.excludes), self._stringify(self.only)))

    def match(self, subject: "Principal") -> bool:
        _match = matches_pattern(pattern=self.identifier, string=subject.identifier)

        if not _match:
            return False

        if self.only:
            return any([matches_pattern(pattern=p.identifier, string=subject.identifier) for p in self.only])

        if self.excludes:
            for p in self.excludes:
                if matches_pattern(pattern=p.identifier, string=subject.identifier):
                    return False

        return _match
