from abc import ABC, abstractmethod
from iam_audit.findings import Finding


class BaseCheck(ABC):

    @abstractmethod
    def run(self, policy: dict) -> list[Finding]:
        """Run this check against a loaded policy document.

        Args:
            policy: A policy dict as returned by loader.load_policy().

        Returns:
            A list of Finding objects. Empty list means no issues found.
        """