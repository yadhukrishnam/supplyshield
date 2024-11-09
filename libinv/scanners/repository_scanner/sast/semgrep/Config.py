import logging

logger = logging.getLogger("sast_configpy")


class Config:
    def __init__(self, args) -> None:
        self.base_code_directory = args.d  # relative path from run , where repo is clond
        self.wasp = args.wasp
