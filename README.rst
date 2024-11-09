===============
SupplyShield
===============

SupplyShield is an application security orchestration tool for DevSecOps requirements.

|Python 3.10+| |stability-wip|

.. |Python 3.10+| image:: https://img.shields.io/badge/python-3.10+-green.svg
   :target: https://www.python.org/downloads/release/python-3100/
.. |stability-wip| image:: https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg

SupplyShield leverages primarily the following tools:

#. `cdxgen <https://github.com/CycloneDX/cdxgen>`_: For generating codebase SBOM
#. `osv <https://osv.dev/>`_: SCA database for cdxgen
#. `syft <https://github.com/anchore/syft/>`_: For generating docker container SBOM
#. `grype <https://github.com/anchore/grype/>`_: For generating docker container SCA
#. `ScancodeIO <https://github.com/supplyshield/scancodeio/>`_: Pipeline for SupplyShield scans
#. `Semgrep <https://semgrep.dev/>`_: SAST Engine

SupplyShield is under active development, releases are available under the "releases" section on GitHub.

Read more about SupplyShield at [docs](./docs/_build/html)

SupplyShield tech stack is Python, Flask, PostgreSQL and Docker and
several libraries.

Copyright notice
^^^^^^^^^^^^^^^^^

Copyright (c) SupplyShield and others. All rights reserved.
