Cron
^^^^

SupplyShield cron helps in syncing with existing Jira tracker and ingests the security metrics in order to show them on a
unified dashboard.

The cron functionality is also leveraged by other syncing methods such as getting all pod/subpod
mappings from a specific external endpoint called the metapod. 

SupplyShield expects the following contract from metapod to sync pod and subpod. 

.. code-block:: python

    {
        "details": [
            {
            "name": "repository_name",
            "subpod": {
                "name": "subpod_name",
                "pod": {
                "name": "pod_name"
                }
            }
            },
            ...
        ]
    }
