from dataclasses import dataclass
from typing import Callable

from afterlife.models import Severity


@dataclass
class Rule:
    id: str
    title: str
    description: str
    default_severity: Severity
    evaluate: Callable
