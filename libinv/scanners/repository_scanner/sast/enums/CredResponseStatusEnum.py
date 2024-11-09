from enum import Enum


class CredResponseStatusEnum(Enum):
    STATUS404 = 0
    STATUSNOROUTEMATCHED = 1
    STATUSUNAUTH = 2
    STATUSNAMERESOLUTIONFAILED = 3
    STATUS405 = 4
    STATUSVALID = 5
