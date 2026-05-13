from pathlib import Path

from afterlife.collectors.base import Collector


class GitHubCollector(Collector):
    source = "github"

    def __init__(self, token: str, org: str, db_path: Path):
        super().__init__(db_path)
        self.token = token
        self.org = org

    def run(self) -> int:
        # Week 3 implementation plan:
        #   - GET /orgs/{org}/members          → Identity(source="github")
        #   - GET /orgs/{org}/outside_collaborators
        #   - GET /orgs/{org}/credential-authorizations (Enterprise; SAML SSO PATs)
        #   - GET /orgs/{org}/installations    → OAuth / GitHub Apps
        #   - GET /repos/{org}/{repo}/keys     → deploy keys (iterate org repos)
        #   - email correlation via GET /users/{username} when available
        raise NotImplementedError("GitHub collector — implement in Week 3")
