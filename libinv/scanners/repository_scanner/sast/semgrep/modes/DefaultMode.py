import re

from libinv.scanners.repository_scanner.sast.enums.PriorityEnum import PriorityEnum


class DefaultMode:
    def __init__(self, config):
        self.config = config
        self.mode = "DEFAULT"
        self.highpriority_ruleid_regex = [r"^generic\.secrets\.security\."]

    def get_vuln_paths(self, sarif_row):
        return []

    def get_publicpaths_priority(self, semgrep, extras):
        ruleid = semgrep["ruleId"]

        for rule_rgx in self.highpriority_ruleid_regex:
            if re.search(rule_rgx, ruleid):
                return (PriorityEnum.HIGH, {})

        return (PriorityEnum.MEDIUM, {})  # this is too coupled.. need to fix.. # default
