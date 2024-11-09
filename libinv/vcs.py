import os
import time
from abc import ABC
from abc import abstractmethod

import jwt
import requests

from libinv.env import GITHUB_APP_APP_ID
from libinv.env import GITHUB_APP_INSTALLATION_ID
from libinv.env import GITHUB_APP_PRIVATE_KEY_FILE


class VcsApp(ABC):
    machine = None
    login = None
    NETRC_FILE = os.path.expanduser("~/.netrc")
    token_expiry = None

    @abstractmethod
    def authenticate(self):
        """
        Abstract method to authenticate with the Git provider.
        """
        raise NotImplementedError

    @abstractmethod
    def get_token(self):
        raise NotImplementedError

    def has_token_expired(self):
        """
        Checks if the token is expired or will expire in less than 30 minutes.
        Overrride for PAT.
        """
        if self.token_expiry is None or self.token is None:
            return True

        current_time = time.time()
        return (self.token_expiry - current_time) < (30 * 60)

    def write_token_to_netrc(self, token):
        """
        Writes the token to the .netrc file.
        """
        with open(self.NETRC_FILE, "w") as netrc_file:
            netrc_file.write(f"machine {self.machine}\n")
            netrc_file.write(f"login {self.login}\n")
            netrc_file.write(f"password {token}\n")

    def authenticate(self):
        """
        Authenticates the app and fetches a token if expired.
        """
        if self.has_token_expired():
            token = self.get_token()
            self.write_token_to_netrc(token)

        assert os.path.exists(self.NETRC_FILE)


class GitHubApp(VcsApp):
    machine = "github.com"
    login = "x-access-token"

    def __init__(self):
        self.api_url = "https://api.github.com"
        self.app_id = GITHUB_APP_APP_ID
        self.installation_id = GITHUB_APP_INSTALLATION_ID
        self.private_key = open(GITHUB_APP_PRIVATE_KEY_FILE).read()
        self.token_endpoint = f"/app/installations/{self.installation_id}/access_tokens"

    def get_token(self):
        headers = {
            "Authorization": f"Bearer {self.generate_jwt()}",
            "Accept": "application/vnd.github.v3+json",
        }
        response = requests.post(f"{self.api_url}{self.token_endpoint}", headers=headers)

        assert response.status_code == 201

        token_data = response.json()
        token = token_data.get("token")
        expires_at = token_data.get("expires_at")
        expiry_time = time.mktime(time.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ"))

        self.token = token
        self.token_expiry = expiry_time

        return token

    def generate_jwt(self):
        """
        Generates a JWT for authenticating with GitHub using the app's private key.
        """

        payload = {"iat": int(time.time()), "exp": int(time.time()) + (10 * 60), "iss": self.app_id}
        token = jwt.encode(payload, self.private_key, algorithm="RS256")
        return token
