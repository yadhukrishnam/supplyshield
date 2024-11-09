from libinv.cli.cli import cli
from libinv.jira_integration import connect


@cli.command()
def secbugs_connect():
    """
    Connect Jira SECBUGS
    """
    connect()
