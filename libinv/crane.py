from pathlib import Path

from libinv.env import CRANE_BIN
from libinv.helpers import subprocess_run


def registry_login(username: str, password: str, registry: str):
    subprocess_run(
        [CRANE_BIN, "auth", "login", "--username", username, "--password-stdin", registry],
        input=password,
    )


def save(image: str, platform: str, outfile: str, insecure=False):
    Path(outfile).parent.mkdir(exist_ok=True, parents=True)
    if insecure:
        return subprocess_run(
            [CRANE_BIN, "pull", "--insecure", "--platform", platform, image, outfile],
        ).stdout.strip()
    return subprocess_run(
        [CRANE_BIN, "pull", "--platform", platform, image, outfile],
    ).stdout.strip()


def digest(image: str, platform: str, insecure=False):
    if insecure:
        return subprocess_run(
            [CRANE_BIN, "digest", "--insecure", "--platform", platform, image],
        ).stdout.strip()
    return subprocess_run([CRANE_BIN, "digest", "--platform", platform, image]).stdout.strip()
