from enum import Enum


class ValidEnum(Enum):
    NOTVALIDATED = 0
    VALIDATED = 1
    FALSEPOSITIVE = 2
    DUPLICATE = 3
