import json
import traceback

import click

from libinv import poll
from libinv import process_message
from libinv.cli.cli import cli
from libinv.helpers import send_to_slack


@cli.command()
@click.option("--slack/--no-slack", is_flag=True, default=True)
@click.pass_context
def daemon(ctx, slack=True):
    """
    Poll messages from sqs queue and populate libinv database
    """
    click.echo("starting service")
    if not ctx.obj["slack_logging"]:
        click.echo("Overriding slack logs. Disabled")
        slack = False
    while True:
        click.echo("polling for new messages")
        messages = poll()
        for message in messages:
            try:
                process_message(message)
            except Exception:
                if not slack:
                    raise

                txt = ":alert: *Error while handling message:*\n"
                txt += "```"
                txt += json.dumps(message)
                txt += "```\n"
                send_to_slack(txt)
                trace = traceback.format_exc()
                chunk_size = 3900
                txt = "*Stack trace:*\n"
                txt += "```"
                txt += trace[0:chunk_size]
                txt += "```"
                send_to_slack(txt)
                if trace:
                    for start in range(chunk_size, len(trace), chunk_size):
                        txt = "```"
                        txt += trace[start : start + chunk_size]
                        txt += "```"
                        send_to_slack(txt)
                click.echo("Error sent to slack. Exiting")
                return
