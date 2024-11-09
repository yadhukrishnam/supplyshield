Web Service
^^^^^^^^^^^

The SupplyShield Web service is a Flask-based Web application that hosts:

#. Actionables dashboard
#. A triager dashboard
#. APIs for 3rd party integrations
#. This documentation

The APIs are meant for anything that could require a web app frontend in SupplyShield.

Actionables Dashboard
*********************

This dashboard helps development teams to trace a vulnerable dependency chain. It can be found at
``http://<host>/actionable/``. The dashboard is populated by the ScanCode.io pipeline.

Triager Dashboard
*****************

SAST components deployed in SupplyShield might detect false positives, thus they are required to be verified
by a triager. The SAST Triage dashboard can be found at: 
``http://<host>/libinv/sast/<SAST_REPORT_UNIQUE_IDENTIFIER>``

Documentation
*************

This documentation is available at ``http://<host>/docs``. 
