# pylint: disable=no-member
import base64
import os
from pathlib import Path

import docker
from attrs import define
from attrs import field

import libinv.crane as crane


@define
class EcrClient:
    boto3_ecr_client = field()
    authorization_token = field(init=False)
    registry = field(init=False)
    local_install = field(default=False)  # Enable when running libinv locally

    def __attrs_post_init__(self):
        self.authorization_token = self.boto3_ecr_client.get_authorization_token()
        creds = self.get_ecr_creds()
        self.registry = creds["registry"]
        crane.registry_login(**creds)

    def pagninate_ecr(self, nextToken, list_of_repos):
        paginate = self.boto3_ecr_client.describe_repositories(nextToken=nextToken)
        for repo in paginate["repositories"]:
            list_of_repos.append(repo["repositoryName"])
        if paginate.get("nextToken") is not None:
            self.pagninate_ecr(paginate.get("nextToken"), list_of_repos)

    def get_list_of_repositories(self):
        # get the list of repos
        paginate = self.boto3_ecr_client.describe_repositories()
        list_of_repos = []
        for repo in paginate["repositories"]:
            list_of_repos.append(repo["repositoryName"])
        if "nextToken" in paginate:
            self.pagninate_ecr(paginate.get("nextToken"), list_of_repos)
        return list_of_repos

    def get_latest_image(self, repositoryName):
        jmespath_expression = "sort_by(imageDetails, &to_string(imagePushedAt))[-1].imageDigest"
        paginator = self.boto3_ecr_client.get_paginator("describe_images")
        iterator = paginator.paginate(repositoryName=repositoryName)
        filter_iterator = iterator.search(jmespath_expression)
        result = list(filter_iterator)[0]
        if result is None:
            pass
        else:
            return result

    def get_ecr_creds(self):
        # https://serverfault.com/questions/856485/how-to-connect-to-aws-ecr-using-python-docker-py
        token = self.authorization_token["authorizationData"][0]["authorizationToken"]
        token = base64.b64decode(token).decode()
        username, password = token.split(":")
        registry = self.authorization_token["authorizationData"][0]["proxyEndpoint"]
        registry = registry.lstrip("https://")
        auth_config = {"username": username, "password": password, "registry": registry}
        return auth_config

    def get_docker_client(self) -> docker.DockerClient:
        """
        THIS DOES NOT WORK because libinv is deployed inside a container and there is no docker
        daemon in a container
        """
        client = docker.from_env()
        creds = self.get_ecr_creds()
        client.login(
            username=creds["username"], password=creds["password"], registry=creds["registry"]
        )
        return client

    def auth(self):
        creds = self.get_ecr_creds()
        username = creds["username"]
        password = creds["password"]
        registry = creds["registry"].split("://")[1]
        HOME_PATH = str(Path.home())
        if os.path.exists(HOME_PATH + "/.docker/config.json") is False:
            os.mkdir(HOME_PATH + "/.docker")
            open(HOME_PATH + "/.docker/config.json", "w+")

        f = open(HOME_PATH + "/.docker/config.json", "w")
        auth_json = (
            '{"auths":{"'
            + registry
            + '":{"username":"'
            + username
            + '","password":"'
            + password
            + '"}}}'
        )
        f.write(auth_json)
        return
