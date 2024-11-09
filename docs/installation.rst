Installation
===============

Run with Docker
----------------

Get Docker
^^^^^^^^^^

The first step is to download and install Docker on your platform. 
Refer to Docker documentation and chose the best installation for your system.

Build the image
^^^^^^^^^^^^^^^

SupplyShield is distributed with ``Dockerfile`` and ``docker-compose.yml`` files
required for the deploying the application.

.. code-block:: bash
    git clone https://github.com/supplyshield/supplyshield
    cd supplyshield
    docker compose build

Configuration
^^^^^^^^^^^^^

SupplyShield requires a configuration file to run. Configuration file can be created by modifying the ``docker.env`` file. 
Refer to the ``docker.env`` file for the configuration options.

SupplyShield consumes messages from an AWS SQS queue. The queue URL, AWS credentials and region need to be configured in
the ``docker.env`` file. Your organization's CI/CD pipeline should be configured to send messages to this SQS queue. 
The messages should be in the format specified in the `Wasp <wasp_>`_.

Run the application
^^^^^^^^^^^^^^^^^^^

Once the image is built, it needs to be configured to run the application. 
You can run the application using the following command:

.. code-block:: bash
    docker compose up

At this point, SupplyShield would have started and would be listening for scan requests. 

.. note::
    This will start:
        1. A PostgreSQL database
        2. SupplyShield API service
        3. SupplyShield Daemon service
        4. SupplyShield Cron service
        5. An empty Metabase instance

Interface
----------

SupplyShield currently provides an interface using metabase.
