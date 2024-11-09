import logging
import os
import subprocess
import time

import schedule

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("libinv.cron-scheduler")

JOBS = {
    "sync_metapod": {
        "command": "libinv --debug import-and-improve-from-metapod",
        "timeout": 600,
        "interval": 600,
    },
    "sync_jira": {
        "command": "libinv --debug secbugs-connect",
        "timeout": 600,
        "interval": 600,
    },
    "sync_metabase": {
        "command": "/app/etc/scripts/metabase_cron.sh",
        "timeout": 600,
        "interval": 300,
    },
}


def execute_command(command, timeout):
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ),
        )
        stdout, stderr = process.communicate(timeout=timeout)

        logger.debug(f"Output: {command}")
        logger.debug(f"Stdout: {stdout.decode().strip()}")
        logger.debug(f"Stderr: {stderr.decode().strip()}")
    except subprocess.TimeoutExpired:
        process.kill()
        logger.error(f"Failed: {command} timed out after {timeout} seconds.")


def run_all_once():
    for job_name, job_details in JOBS.items():
        logger.debug(f"Running job '{job_name}'")
        execute_command(job_details["command"], job_details["timeout"])


def schedule_jobs():
    for job_name, job_details in JOBS.items():
        schedule.every(job_details["interval"]).seconds.do(
            execute_command, command=job_details["command"], timeout=job_details["timeout"]
        )
        logger.debug(f"Scheduled job '{job_name}' every {job_details['interval']} seconds.")


def main():
    logger.debug("Starting cron scheduler")
    run_all_once()
    schedule_jobs()
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
