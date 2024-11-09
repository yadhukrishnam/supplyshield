.. _wasp:

Daemon
^^^^^^

SupplyShield Daemon facilitates the orchestration to invoke multitude of codebase scanning in a non
blocking mode. It listens to all deployment messages via a SQS queue to perform relevant
scans such as run SBOM, SCA, SAST and other automations on the top of codebases being deployed.

.. image:: images/daemon.svg
   :width: 600
   :alt: daemon flow

Wasp
****

In order to receive messages from a build system, daemon uses a JSON contract known
as Wasp. A wasp contract requires the following fields:

.. code-block:: javascript

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

The above contract supports builds with multi-arch images on AWS ECR.

.. image:: images/daemon-explained.svg
   :width: 600
   :alt: daemon flow explained


ScanCode.io
^^^^^^^^^^^

We use ScanCode.io as our pipeline to find actionables. Our aim is to move as much of the
SupplyShield codebase to ScanCode.io in order to benefit the community. This is a long term effort and we
have made some success in the process.

Currently, ScanCode.io goes through 3 stages for every build received.

#. It populates internal SBOM schema by taking in a standard CycloneDX SBOM from the S3 URL
   provided.
#. Run Google's OSV scanner to find out SCA vulnerabilities present in the provided SBOM.
#. Find actionables for development teams in simple yet functional terms as supply chain
   vulnerabilities can reside deep inside the package dependency chain unknown to the development
   team.

.. image:: images/libinv-Scancodeio.drawio.svg
   :width: 400
   :alt: ScanCode.io
   :align: center

