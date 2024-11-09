import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from git import Repo
from git.exc import GitCommandError
from sqlalchemy import CHAR
from sqlalchemy import JSON
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import delete
from sqlalchemy import func
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import declarative_mixin
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.orm import synonym
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.sql.expression import ClauseElement

from libinv.base import Base
from libinv.base import Session
from libinv.base import conn
from libinv.env import EXCLUDED_REPOS
from libinv.env import LIBINV_TEMP_DIR
from libinv.exceptions import ConflictingInfoError
from libinv.exceptions import MalformedCaterpillarMessage
from libinv.helpers import case_insensitive_dict
from libinv.helpers import explode_git_url
from libinv.vcs import GitHubApp

MAX_LENGTH_LICENSE = 150
MAX_LENGTH_VULNERABILITY_DESCRIPTION = 500
ORGSRE_ACCOUNT_ID = "orgsre"

logger = logging.getLogger(__name__)


class PackageLicenseAssociation(Base):
    __tablename__ = "package_license_association"

    package_id = Column(
        ForeignKey("libinv.packages.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    license_id = Column(
        ForeignKey("libinv.license_family.id", onupdate="CASCADE", ondelete="CASCADE"),
        primary_key=True,
    )

    package = relationship("Package", back_populates="licenses")
    license = relationship("License", back_populates="packages")


@declarative_mixin
class TimestampMixin:
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Image(Base, TimestampMixin):
    __tablename__ = "images"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    backend_tech = Column(String(24))
    account_id = Column(
        ForeignKey("libinv.accounts.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False
    )
    digest = Column(String(72), nullable=False)
    tag = Column(String(128))
    commit = Column(String(128))
    platform = Column(String(24), nullable=False)
    parent_image_id = Column(ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"))
    base_image_id = Column(ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"))
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    wasp_id = Column(ForeignKey("libinv.wasps.id", onupdate="CASCADE", ondelete="CASCADE"))

    parent_image = relationship("Image", remote_side=[id], foreign_keys=[parent_image_id])
    base_image = relationship("Image", remote_side=[id], foreign_keys=[base_image_id])
    packages = relationship("ImagePackageAssociation", back_populates="image")
    layers = relationship("Layer", back_populates="image")
    repository = relationship("Repository", back_populates="images")
    wasp = relationship("Wasp", back_populates="images")

    def __str__(self):
        return f"{self.name}-{self.id}"

    @property
    def sorted_layers(self) -> str:
        return sorted(self.layers, key=lambda x: x.seq)

    def is_parent_image_of(self, other: "Image"):
        """
        Return True if self is a parent image of other.
        Parent image is a different image that contains all the layers of child and no more.
        """
        other_layers = other.sorted_layers
        self_layers = self.sorted_layers

        if len(self_layers) >= len(other_layers):
            return False

        for seq, layer in enumerate(self.sorted_layers):
            if layer != other_layers[seq]:
                return False
        return True

    @classmethod
    def get_by_id(cls, session, image_id):
        return session.get(Image, {"id": image_id})

    @classmethod
    def get_all_dev_image_ids(cls, session):
        ids = session.query(Image.id).filter(Image.account_id != ORGSRE_ACCOUNT_ID)
        return list(map(lambda x: x[0], ids))  # because sqlachemy returns tuples in ids


class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    version = Column(String(150))
    language = Column(String(20))
    purl = Column(String(300), unique=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.current_timestamp())
    images = relationship("ImagePackageAssociation", back_populates="package")
    licenses = relationship("PackageLicenseAssociation", back_populates="package")
    vulnerabilities = relationship("VulnerabilityPackageAssociation", back_populates="package")

    def __str__(self):
        return self.purl


class ImagePackageAssociation(Base):
    __tablename__ = "image_package_association"

    image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    package_id = Column(
        ForeignKey("libinv.packages.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    pkg_metadata = Column("metadata", Text)

    image = relationship("Image", back_populates="packages")
    package = relationship("Package", back_populates="images")

    Index("not-null-metadata", pkg_metadata, mysql_length=1)


class VulnerabilityPackageAssociation(Base):
    __tablename__ = "vulnerability_package_association"
    vulnerability_id = Column(
        String(50),
        ForeignKey("libinv.vulnerabilities.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )
    package_id = Column(
        Integer,
        ForeignKey("libinv.packages.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )
    fix = Column(String(100), doc="comma seperated list of fix versions", nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="packages")
    package = relationship("Package", back_populates="vulnerabilities")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(50), primary_key=True)
    description = Column(String(MAX_LENGTH_VULNERABILITY_DESCRIPTION))
    severity = Column(String(10))
    related = Column(String(200), doc="comma seperated list of related cve ids")
    nvd_cvss_base_score = Column("nvd-cvss.base_score", Float(precision=3))
    nvd_cvss_exploitability_score = Column("nvd-cvss.exploitability_score", Float(precision=3))
    nvd_cvss_impact_score = Column("nvd-cvss.impact_score", Float(precision=3))
    packages = relationship("VulnerabilityPackageAssociation", back_populates="vulnerability")

    def set_desciption(self, desc: str):
        if desc:
            self.description = desc[:MAX_LENGTH_VULNERABILITY_DESCRIPTION]

    def __str__(self):
        return self.id


class License(Base):
    __tablename__ = "license_family"

    id = Column(Integer, primary_key=True)
    name = Column(String(MAX_LENGTH_LICENSE), unique=True)
    packages = relationship("PackageLicenseAssociation", back_populates="license")

    def set_license_name(self, name):
        if name:
            self.name = name[:MAX_LENGTH_LICENSE]


class Layer(Base, TimestampMixin):
    __tablename__ = "layers"
    id = Column(CHAR(length=64), primary_key=True)
    image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    seq = Column(Integer, primary_key=True, nullable=False)
    image = relationship("Image", back_populates="layers")

    def __eq__(self, other):
        return self.id == other.id and self.seq == other.seq

    def __str__(self):
        return self.id


class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True)
    provider = Column(String(200), nullable=False)
    org = Column(String(200), nullable=False)
    name = Column(String(200), nullable=False)
    is_public = Column(Boolean, default=False, nullable=False)
    images = relationship("Image", back_populates="repository")
    secbugs = relationship("Secbug", back_populates="repository")
    pod = Column(String(200))
    subpod = Column(String(200))

    UniqueConstraint("org", "name", name="org_repo")

    def __str__(self):
        return self.url

    @property
    def url(self):
        return f"git@{self.provider}:{self.org}/{self.name}"

    @classmethod
    def from_url(cls, url):
        return Repository(**explode_git_url(url))


class Account(Base):
    __tablename__ = "accounts"
    id = Column(String(12), primary_key=True)
    name = Column(String(50))
    type = Column(String(10), server_default="stage", nullable=False)

    def is_prod(self):
        return self.type == "prod"

    @classmethod
    def ensure_exists(cls, account_id, name=None, account_type="stage"):
        """
        Create Account if it does not exist, nop otherwise
        """
        if not conn.query(cls).filter(cls.id == account_id).one_or_none():
            if not name:
                raise ValueError(
                    f"Account id: {account_id} does not exist. Cannot create new account without a name"
                )
            new_account = cls(id=account_id, name=name, type=account_type)
            conn.add(new_account)
            logger.info(f"Created new account id: {account_id} name: {name} type: {account_type}")


class DeploymentCheckpoint(Base, TimestampMixin):
    __tablename__ = "deployment_checkpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    active: Mapped[int] = mapped_column(default=False, nullable=False)
    checkpoint: Mapped[datetime] = mapped_column(nullable=False)

    def __str__(self):
        return f"{self.checkpoint}"

    @classmethod
    def get(cls, session):
        return session.query(DeploymentCheckpoint).filter_by(active=True).one_or_none()

    @classmethod
    def set(cls, session, checkpoint):
        old_checkpoint = cls.get(session)
        if old_checkpoint:
            old_checkpoint.active = False
            session.add(old_checkpoint)
        checkpoint, _ = get_or_create(session, DeploymentCheckpoint, checkpoint=checkpoint)
        checkpoint.active = True
        LatestImage.callibrate(session, checkpoint)
        session.add(checkpoint)
        session.commit()
        return checkpoint

    @classmethod
    def list(cls, session):
        checkpoints = session.query(DeploymentCheckpoint).all()
        return checkpoints


class LatestImage(Base):
    """
    Latest images as per DeploymentCheckpoint
    """

    __tablename__ = "latest_images"
    image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    account_id = Column(
        ForeignKey("libinv.accounts.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )  # This helps to speed up joins with account table

    @classmethod
    def callibrate(cls, session, checkpoint):
        """
        Callibrate latest images as per given checkpoint. Images after the checkpoints are not
        considered
        """
        session.execute(delete(LatestImage))
        stmt = text(
            """
        INSERT INTO latest_images
        SELECT
              images.id, images.account_id
          FROM
              images
              INNER JOIN (
                      SELECT
                          name,
                          account_id,
                          platform,
                          max(created_at) AS created_at
                      FROM
                          images
                      WHERE created_at <= :checkpoint
                      GROUP BY
                          name, account_id, platform
                  )
                      AS finder -- finder has latest image data
                      ON
                      images.name = finder.name
                      AND images.account_id
                          = finder.account_id
                      AND images.platform = finder.platform
                      AND images.created_at
                          = finder.created_at;
           """
        )
        session.execute(stmt, {"checkpoint": checkpoint})


class Secbug(Base, TimestampMixin):
    __tablename__ = "secbugs"

    id = Column(String(50), primary_key=True)
    environment = Column(String(20))
    severity = Column(String(10))
    description = Column(String(MAX_LENGTH_VULNERABILITY_DESCRIPTION))
    vulnerability_category = Column(String(40))
    identified_by = Column(String(40))
    company = Column(String(20))
    is_risk = Column(Boolean())
    pulled_at = Column(DateTime(), nullable=False)
    deleted_at = Column(DateTime(), nullable=True)
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE", ondelete="CASCADE")
    )

    repository = relationship("Repository", back_populates="secbugs")
    key = synonym("id")

    def __str__(self):
        return self.id

    def delete(self):
        """
        perform soft delete
        """
        self.deleted_at = datetime.now()

    def is_active(self):
        return True if self.deleted_at else False

    @classmethod
    def get(cls, id: str):
        return cls.all_active().filter(cls.id == id).first()

    @classmethod
    def all_active(cls):
        return conn.query(cls).filter(cls.deleted_at == None)  # noqa: E711


class Wasp(Base, TimestampMixin):  # Wasp eats caterpillars
    """
    A wasp eats catterpillar messages using ``eat_caterpillar_message`` function.
    """

    __tablename__ = "wasps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String(36), nullable=False, unique=True, default=uuid4)
    repository_id = Column(ForeignKey("libinv.repositories.id", onupdate="CASCADE"))
    tag = Column(String(128))
    commit = Column(String(128))
    environment = Column(String(128))
    jenkins_url = Column(String(256))
    raw_message = Column(String(2048), nullable=False)
    ate_successfully = Column(Boolean(), nullable=False, default=True, server_default="1")
    complaints = Column(Text, default="")

    images = relationship("Image", back_populates="wasp")
    repository = relationship("Repository")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type == MalformedCaterpillarMessage:
            logger.error(exc_value)
            return True

        if exc_type:
            self.throw(f"{exc_type} : {exc_value} : {traceback}")

        conn.add(self)
        conn.commit()
        logger.debug(f"Cleaning up wasp {self}")
        if hasattr(self, "_project_dir"):
            shutil.rmtree(self._project_dir)
            logger.debug(f"Delete {self._project_dir}")

        return True

    def __str__(self):
        return f"{self.uuid}"

    @classmethod
    def eat_caterpillar_message(cls, message: dict):
        """
        Messages are eaten as per the following agreement:

        {
            "repository": {
                "url": URL,
                "commit": COMMIT_ID,
                "tag": TAG,
                "commit_author": COMMIT_AUTHOR (To be implemented later)
            },
            "aws_environment": stage/papg/prod,
            "job_url": jenkins_url,
            "buildx_enabled": true/false
            "ecr_image": [{
                "name": <URI upto tag part (ie : )>,
                "digest": DIGEST,
                "type": "Image" or "ImageIndex",
                "platform": <Only present for Image>
            }...]
        }
        """
        repository_url = message["repository"]["url"]
        commit = message["repository"]["commit"]
        tag = message["repository"]["tag"]
        raw_message = json.dumps(message)
        environment = message["aws_environment"]
        jenkins_url = message["job_url"]

        if is_excluded_repo(repository_url):
            logger.error(f"[!] Excluded repository: {repository_url}")
            return

        repository, created = get_or_create(conn, Repository, **explode_git_url(repository_url))
        if created:
            logger.debug(f"[*] Created repository: {repository}")

        # sql constraint might take care of null/None value, ensure it's not empty ("")
        if not repository.name or not repository.url or not repository.provider:
            raise MalformedCaterpillarMessage(
                f"Repository details cannot be empty, repository: {repository}"
                f" given url: {repository_url}"
            )

        wasp = cls(
            repository=repository,
            tag=tag,
            commit=commit,
            raw_message=raw_message,
            environment=environment,
            jenkins_url=jenkins_url,
        )
        conn.add(wasp)
        conn.commit()
        logger.info(f"Wasp ate caterpillar: {wasp}")
        return wasp

    @property
    def cwd(self) -> Path:
        return Path(LIBINV_TEMP_DIR)

    def throw(self, why: str):
        """
        Throw some food out. Specify why any actions on wasp failed without failing entire libinv
        """
        try:
            conn.connection()
        except PendingRollbackError:
            conn.rollback()

        self.complaints += why
        self.ate_successfully = False
        logger.error(f"{self} raised: {why}")

    @property
    def project_dir(self) -> Path:
        """
        Return a dir for this wasp to keep all its files.
        Treat this as a temp dir that will be emptied when the wasp dies
        """
        if not hasattr(self, "_project_dir"):
            self._project_dir = Path(self.cwd, self.uuid)
            print(self._project_dir)
            self._project_dir.mkdir(exist_ok=True, parents=True)

        return self._project_dir

    @property
    def repo_dir(self):
        if not hasattr(self, "_repo_dir"):
            self._repo_dir = self.clone()

        return self._repo_dir

    def clone(self):
        """
        Return dir after cloning repository given to to wasp
        """
        repository = self.repository
        commit = self.commit
        if self.repository.provider == "github.com":
            github = GitHubApp()
            github.authenticate()
        else:
            raise NotImplementedError(
                f"Repository provider: {self.repository.provider} not implemented"
            )

        logger.debug(f"[*] Cloning {self.repository.url}")
        target_dir = Path(self.project_dir, f"{repository.name}-{commit[:10]}")
        Path(target_dir).mkdir(exist_ok=True)
        try:
            print("Trying to clone now..", flush=True)
            # FIXME: temporary fix for cloning until SRE fixes this
            https_url = repository.url.replace("git@github.com:", "https://github.com/")
            repo = Repo.clone_from(https_url, target_dir)
        except GitCommandError as e:
            logger.error(e)
        try:
            repo.git.checkout(commit)
        except GitCommandError:
            self.throw(f"commit does not exist: {commit}")
            raise

        assert repo.head.is_detached
        logger.info(f"[+] Cloned {repository}")
        return target_dir


class SastLobMetaData(Base, TimestampMixin):
    """
    stores metadata related to each LOB
    """

    __tablename__ = "sast_lob_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repository = relationship("Repository")
    module = Column(String(1024), nullable=False)
    sub_module = Column(String(1024), nullable=False)
    repository_id = Column(ForeignKey("libinv.repositories.id", onupdate="CASCADE"))

    bugcounts = Column(Integer, default=0)

    Index("idx_repository", repository_id)


class SastResult(Base, TimestampMixin):
    """
    stores result from semgrep of the rules
    """

    __tablename__ = "sast_result"

    id = Column(String(150), primary_key=True)
    lob_id = Column(ForeignKey("libinv.sast_lob_metadata.id", onupdate="CASCADE"))
    lob_metadata = relationship("SastLobMetaData")
    extras = Column(JSON)
    vulnsnippet = Column(Text)
    githubpath = Column(String(1024))
    secbugurl = Column(String(1024))
    file_path = Column(String(1024))
    priority = Column(String(20))
    confidence = Column(String(20))
    description = Column(Text)
    public_initial_point = Column(Text)
    source = Column(String(200))
    isactive = Column(Boolean)
    wasp_id = Column(ForeignKey("libinv.wasps.id", onupdate="CASCADE", ondelete="CASCADE"))
    fixed_date = Column(DateTime)
    validated = Column(Integer)  # 0=not validted yet, 1=valid bug, 2=false positive/intended
    validate_date = Column(DateTime)
    secbug_created_date = Column(DateTime)
    mean_solve_time = Column(Integer)


# https://stackoverflow.com/a/2587041/2251364
def get_or_create(session, model, defaults=None, **kwargs):
    instance = session.query(model).filter_by(**kwargs).one_or_none()
    if instance:
        return instance, False
    else:
        params = {k: v for k, v in kwargs.items() if not isinstance(v, ClauseElement)}
        params.update(defaults or {})
        instance = model(**params)
        session.add(instance)
        session.commit()
        return instance, True


def filter_model_collection(model_collection, filter_map: dict):
    """
    Return filtered models from a model collection (say, relationship) according to given filter map
    filter_map must not have any other field than that in model
    """
    filtered = []

    # Because mysql >:()
    filter_map = case_insensitive_dict(filter_map)

    for model in model_collection:
        # Because mysql >:()
        model_dict = case_insensitive_dict(model.__dict__)
        if filter_map.items() <= model_dict.items():
            filtered.append(model)
    return filtered


def get_base_image_of(image: Image) -> "Image":
    """
    Return base image nor None
    Base image is defined as top node of parent image hirarchy.
    """
    base = image.parent_image
    while base.parent_image:
        base = base.parent_image
    return base


def update_safely(session: Session, model: Base, attr: str, value: object):
    existing_value = getattr(model, attr)
    if existing_value and existing_value != value:
        raise ConflictingInfoError(
            f"{model} already has {attr}: {existing_value}"
            f" and it doesn't match given {attr}: {value}"
        )
    setattr(model, attr, value)
    session.add(model)
    session.commit()


def is_excluded_repo(repository_url):
    git_url_components = explode_git_url(repository_url)
    return f"{git_url_components['org']}/{git_url_components['name']}" in EXCLUDED_REPOS
