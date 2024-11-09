import logging

from libinv.scanners.repository_scanner.sast.semgrep import utils

logger = logging.getLogger("libinv.helpers")


class SemgrepRunner:
    def __init__(self, config):
        self.config = config
        self.rules = [
            "auto"
        ]
        self.output_file = (
            str(config.wasp.project_dir)
            + f"/output/semgrep_result/out_{config.wasp.repository.name}_latest"
        )

    def run_semgrep(self):
        """
        executes the  RULES inside self.rules with semgrep
        this will mostly be same for all Modes.py
        executes the semgrep command and saves the result in output folder
        """

        rules_m = "--config=".join(map(lambda x: f"'{x}' ", self.rules))
        cmd = f"semgrep --no-git-ignore --config={rules_m} --sarif  --timeout 0 --output '{self.output_file}' '{self.config.base_code_directory}'"
        logger.info("[INFO] EXEC Running:: " + cmd)

        utils.exec(cmd)

        return self.output_file

    def run(self):
        self.run_semgrep()
        return
