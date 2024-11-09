from sqlalchemy import Table

from libinv.base import Base
from libinv.base import engine
from libinv.base import metadata


class VulnerablePath(Base):
    __table__ = Table("scanpipe_vulnerablepaths", metadata, schema="public", autoload_with=engine)
