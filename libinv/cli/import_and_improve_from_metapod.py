import requests
from tqdm.contrib.concurrent import process_map

from libinv import Repository
from libinv import Session
from libinv.cli.cli import cli
from libinv.env import GIT_ORG
from libinv.env import GIT_PROVIDER
from libinv.env import SERVICE_METADATA_URL
from libinv.models import get_or_create


def metapod_services():
    return requests.get(SERVICE_METADATA_URL).json()["details"]


def update_and_add_repositories_using_metapod(metapod_service):
    repository_name = metapod_service["name"]
    subpod = metapod_service["subpod"]["name"]
    pod = metapod_service["subpod"]["pod"]["name"]
    with Session() as session:
        repository, _ = get_or_create(
            session=session,
            model=Repository,
            name=repository_name,
            provider=GIT_PROVIDER,
            org=GIT_ORG,
        )
        repository.pod = pod
        repository.subpod = subpod
        session.commit()


@cli.command()
def import_and_improve_from_metapod():
    services = metapod_services()
    process_map(update_and_add_repositories_using_metapod, services, chunksize=20)
