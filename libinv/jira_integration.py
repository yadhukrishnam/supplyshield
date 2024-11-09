import logging
from datetime import datetime

from jira import JIRA

from libinv.base import conn
from libinv.env import JIRA_TOKEN
from libinv.env import JIRA_URL
from libinv.env import JIRA_USER
from libinv.models import MAX_LENGTH_VULNERABILITY_DESCRIPTION
from libinv.models import ConflictingInfoError
from libinv.models import Repository
from libinv.models import Secbug
from libinv.models import get_or_create
from libinv.models import update_safely

logger = logging.getLogger("libinv.jira-integration")


class JiraProject:
    def __init__(self, project_name, user, token):
        self.name = project_name
        self.jira = JIRA(server=JIRA_URL, basic_auth=(user, token))
        self.id = self.jira.project(project_name).id

    def get_customfield_id_by_name(self, name: str):
        """
        Return **first** customfield id where the given name matches scoped for given project id
        """
        for field in self.jira.fields():
            try:
                if name == field["name"] and field["scope"]["project"]["id"] == self.id:
                    return field["id"]
            except KeyError:
                pass
        return None

    def print_customfields(self):
        for field in self.jira.fields():
            try:
                if field["scope"]["project"]["id"] == self.id:
                    print(f"{field['id']}: {field['name']}")
            except KeyError:
                pass
        return None

    @property
    def issues(self):
        return self.jira.search_issues(
            f"project={self.name} "
            'AND status in ("TO DO", "IN PROGRESS") '
            "order by created DESC",
            maxResults=None,
        )


class JiraSecbug(JiraProject):
    def __init__(self):
        super().__init__(project_name="SECBUG", user=JIRA_USER, token=JIRA_TOKEN)


def get_or_update_repository(repository_name: str, pod: str, subpod: str):
    repository = conn.query(Repository).filter(Repository.name == repository_name).one_or_none()
    if not repository:
        logger.error(f"Unknown repository: {repository_name}, lob: {pod}, pod: {subpod}. Skipped")
        # FIXME: We probably want to add this repository, but what's source of truth for pod and
        # subpod ?
        return

    try:
        update_safely(session=conn, model=repository, attr="pod", value=pod)
        update_safely(session=conn, model=repository, attr="subpod", value=subpod)
    except ConflictingInfoError as exc:
        logger.warning(exc)
        # FIXME: Something should be done here, for now we ignore and don't update anything

    return repository


def fix_severity(severity):
    if severity.casefold() == "highest":
        return "Critical"
    if severity.casefold() == "lowest":
        return "Low"
    return severity


def pop_or_none(lst):
    if lst:
        return lst.pop()
    return None


def to_datetime(date_string):
    return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f%z")


def delete_outdated_secbugs(all_fetched_secbug_keys):
    # Why don't we use the "resolved" field ?
    # - It isn't consistent across all secbugs (mostly old ones)

    secbugs_in_db = Secbug.all_active().all()

    for secbug in secbugs_in_db:
        if secbug.key not in all_fetched_secbug_keys:
            logger.debug(f"Will delete {secbug}")
            secbug.delete()

    conn.commit()


def connect():
    secbug = JiraSecbug()
    environment_field_id = secbug.get_customfield_id_by_name("Environment")
    lob_field_id = secbug.get_customfield_id_by_name("APPSEC_POD")
    pod_field_id = secbug.get_customfield_id_by_name("Subpod")
    repo_field_id = secbug.get_customfield_id_by_name("Repo Name")
    company_field_id = secbug.get_customfield_id_by_name("Company")
    vulnerability_category_id = secbug.get_customfield_id_by_name("Vulnerability Category")
    identified_by_id = secbug.get_customfield_id_by_name("Identified By")
    pulled_at = datetime.now()

    delete_outdated_secbugs([issue.key for issue in secbug.issues])

    for issue in secbug.issues:
        logger.debug(f"Processing {issue.key}")
        secbug_id = issue.key

        if Secbug.get(secbug_id):
            logger.debug(f"Already exists, skipping {secbug_id}")
            continue

        logger.info(f"[+] New secbug: {secbug_id}")

        environment = getattr(issue.get_field(environment_field_id), "value", None)
        severity = fix_severity(issue.fields.priority.name)
        description = issue.fields.description
        lob = pop_or_none(issue.get_field(lob_field_id))
        pod = pop_or_none(issue.get_field(pod_field_id))
        created_at = to_datetime(issue.fields.created)
        updated_at = to_datetime(issue.fields.updated)
        repository_names = issue.get_field(repo_field_id)
        company = getattr(issue.get_field(company_field_id), "value", None)
        vulnerability_category = getattr(issue.get_field(vulnerability_category_id), "value", None)
        identified_by = getattr(issue.get_field(identified_by_id), "value", None)

        if repository_names:  # FIXME: Multiple repos?
            repository_name = repository_names[0]
            repository = get_or_update_repository(
                repository_name=repository_name, pod=lob, subpod=pod
            )
            if repository:
                get_or_create(
                    session=conn,
                    model=Secbug,
                    id=secbug_id,
                    environment=environment,
                    severity=severity,
                    description=description[:MAX_LENGTH_VULNERABILITY_DESCRIPTION],
                    repository_id=repository.id,
                    created_at=created_at,
                    updated_at=updated_at,
                    pulled_at=pulled_at,
                    company=company,
                    vulnerability_category=vulnerability_category,
                    identified_by=identified_by,
                )
        else:
            logger.warning(f"No repository data present for {secbug_id}")
            get_or_create(
                session=conn,
                model=Secbug,
                id=secbug_id,
                environment=environment,
                severity=severity,
                description=description[:MAX_LENGTH_VULNERABILITY_DESCRIPTION],
                created_at=created_at,
                updated_at=updated_at,
                pulled_at=pulled_at,
            )
        logger.debug(f"[+] Processed {issue.key}")
