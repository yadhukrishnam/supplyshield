import os
from typing import Optional

from attrs import define

import libinv.crane as crane
from libinv.helpers import SubprocessError
from libinv.scanners.image_scanner.exceptions import ImageNotFoundException


@define
class ImageTarBall:
    """
    Represents a docker image tarball
    A new instance pulls the specified image as tar if it does not already exist
    """

    registry: str
    name: str
    platform: str
    digest: Optional[str] = None
    tag: Optional[str] = None
    freshly_pulled: Optional[bool] = False
    insecure: Optional[bool] = False

    def __attrs_post_init__(self):
        if not self.digest:
            self.digest = crane.digest(
                image=self.qualified_name, platform=self.platform, insecure=True
            )
        image_exists = os.path.exists(str(self))
        if not image_exists:
            self.pull(self.insecure)

    def __str__(self):
        return self.filename

    @property
    def qualified_name(self):
        name = f"{self.registry}/{self.name}"
        if self.tag:
            name += f":{self.tag}"
        if self.digest:
            name += f"@{self.digest}"
        return name

    @property
    def filename(self):
        return "".join([x if x.isalnum() else "_" for x in self.qualified_name]) + ".tar"

    @property
    def size(self):
        return os.stat(str(self)).st_size

    def pull(self, insecure=False):
        try:
            crane.save(
                image=self.qualified_name,
                platform=self.platform,
                outfile=str(self),
                insecure=insecure,
            )
        except SubprocessError as exc:
            raise ImageNotFoundException(str(exc)) from exc
        self.freshly_pulled = True

    def delete(self):
        os.remove(str(self))
