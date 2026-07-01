from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


@dataclass
class Finding:
    check_id: str
    severity: Severity
    title: str
    file: str
    statement_index: int
    description: str
    risk: str
    remediation: str