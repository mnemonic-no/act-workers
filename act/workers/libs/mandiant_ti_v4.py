"""Mandiant V4 api impl"""

import base64
import datetime as DT
import logging
import time
import urllib.parse as urlparse
from typing import Any, Dict, List, Optional

import requests

APP = "mnemonic/mss/act-0.1"


class V4APIError(Exception):
    """Exception class used to report errors from the API"""

    ...


class Connection:
    """Basic Mandiant v4 API connection"""

    def __init__(
        self,
        key_id: str,
        secret_key: str,
        url: str = "https://api.intelligence.mandiant.com",
        application_name: Optional[str] = None,
        proxy_string: Optional[str] = None,
    ) -> None:

        self.url = url

        if not application_name:
            application_name = APP
        self.application_name = application_name
        self.access_token = self.get_token(key_id, secret_key)
        self.proxy_string = proxy_string

        # The rate limits in the API is dynamic, but we set a safe
        # value that should cover all types as
        # 10 calls per second in a 10 second period
        # 5 calls per second in a 60 second period
        # 2 calls per second in a 10-minute period
        # 1 call per second in a 1-hour period
        self.min_millis_requests = 1010  # Minimum milliseconds between API requests
        self.last_request_timestamp: float = 0

    def get_token(self, key_id: str, secret_key: str) -> str:
        """Request an access token from v4"""

        auth_token_bytes = f"{key_id}:{secret_key}".encode("ascii")
        base64_auth_token_bytes = base64.b64encode(auth_token_bytes)
        base64_auth_token = base64_auth_token_bytes.decode("ascii")

        params = {"grant_type": "client_credentials", "scope": ""}

        headers = {
            "Authorization": f"Basic {base64_auth_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "X-App-Name": f"{self.application_name}",
        }

        access_token = requests.post(
            url=urlparse.urljoin(self.url, "token"),
            headers=headers,
            data=params,
        )

        token: Optional[str] = access_token.json().get("access_token", None)
        if token:
            return token

        raise V4APIError("Could not extract 'access_token' from the result")

    def get_headers(self) -> Dict[str, Any]:
        """Return the headers used"""

        headers: Dict[str, Any] = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "X-App-Name": self.application_name,
            "Content-Type": "application/json",
        }

        return headers

    def api_request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send request to API and update current object with result"""

        while (
            time.time() - self.last_request_timestamp
        ) * 1000 < self.min_millis_requests:
            logging.debug("Rate limiting")
            time.sleep(0.1)

        self.last_request_timestamp = time.time()

        proxies = {"https": self.proxy_string} if self.proxy_string else None

        resp = requests.request(
            method,
            urlparse.urljoin(self.url, path),
            headers=self.get_headers(),
            proxies=proxies,
            json=json,
            params=params,
        )

        if resp.status_code >= 300:
            raise V4APIError(resp.text)

        try:
            res: Dict[str, Any] = resp.json()
        except requests.exceptions.JSONDecodeError as err:
            raise V4APIError(f"Unable to decode as json: {resp.text}: {err}")
        return res

    def api_post(self, path: str, **kwargs: Any) -> Dict[str, Any]:
        """Send POST request to API with keywords as JSON arguments"""

        return self.api_request("POST", path, json=kwargs)

    def api_get(self, path: str, **kwargs: Any) -> Dict[str, Any]:
        """Send GET request to API
        Args:
            uri (str):     URI (relative to base url). E.g. "v1/factType"
            params (Dict): Parameters that are URL enncoded and sent to the API"""

        return self.api_request("GET", path, params=kwargs)

    def get_indicators(
        self,
        limit: int = 25,
        gte_mscore: int = 80,
        exclude_osint: bool = True,
        start_epoch: Optional[int] = None,
        end_epoch: Optional[int] = None,
        next_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Returns a paginated list of indicators based on parameters defined in the
        request.

        limit:         Defines the maximum number of results to return. Default 25 and
                       maximum allowed 1000
        gte_mscore:    Defines the minimum Indicator Confidence Score to return.
                       Default 80.
        exclude_osint: Defines if open source indicators should be returned.
                       Default True.
        start_epoch:   Defines the start time of the data to load in epoch format,
                       based on an indicators last_updated value. If not provided,
                       this defaults midnight 7 days ago.
        end_epoch:     Defines the end time of the data to load in epoch format,
                       based on an indicators last_updated value. If not provided,
                       this defaults to now.
        next_token:    Used to get the next page of results. When using next no other
                       parameters will be honored."""
        ...

        if next_token:
            return self.api_post("v4/indicators", next_token=next_token)

        if not start_epoch:
            today = DT.date.today()
            week_ago = today - DT.timedelta(days=7)
            start_epoch = int(DT.datetime(*week_ago.timetuple()[:-6]).timestamp())

        if not end_epoch:
            end_epoch = int(DT.datetime.now().timestamp())

        return self.api_get(
            "v4/indicators",
            limit=limit,
            gte_mscore=gte_mscore,
            exclude_osint=exclude_osint,
            start_epo=start_epoch,
            end_epoch=end_epoch,
        )

    def get_indicators_by_value(self, values: List[str]) -> Dict[str, Any]:
        """
        Returns indicator objects based on a list of indicator values provided
        in the request"""

        return self.api_post("v4/indicator", requests=[{"values": values}])

    def get_malware_families(self) -> List[Dict[str, Any]]:
        """Returns a list of Malware Families tracked by Mandiant."""

        malware: List[Dict[str, Any]] = []

        offset = 0
        limit = 500

        while True:
            res = self.api_post("v4/malware", offset=offset, limit=limit)

            offset += limit

            mwlist = res.get("malware", [])
            if not mwlist:
                return malware
            malware += mwlist

            if res["total_count"] == offset:
                break

        return malware

    def get_malware_attack_patterns(self, ids: List[str]) -> Dict[str, Any]:
        """
        Returns a list of Mitre ATT&CK patterns associated with the Malware Families
        specified request."""

        return self.api_post(
            "v4/malware/attack-pattern",
            ids=ids,
        )

    def get_threat_actors(self) -> List[Dict[str, Any]]:
        """Returns a list of Threat Actors tracked by Mandiant."""

        offset = 0
        limit = 1000
        params = {"offset": offset, "limit": limit}

        tas: List[Dict[str, Any]] = []

        while True:
            res = self.api_get(
                "v4/actor",
                offset=offset,
                limit=limit,
            )

            if not res["threat-actors"]:
                return tas

            tas += res["threat-actors"]

            offset += limit
            params["offset"] = offset

            if offset > res["total_count"]:
                break

        return tas

    def get_threat_actors_attack_patterns(self, ids: List[str]) -> Dict[str, Any]:
        """
        Returns a list of Mitre ATT&CK patterns associated with the
        Threat Actors specified
        """

        return self.api_post(
            "v4/actor/attack-pattern",
            ids=ids,
        )

    def get_threat_actor(self, id: str) -> Dict[str, Any]:
        """
        Return details of a threat actor
        """

        return self.api_get(f"v4/actor/{id}")

    def get_threat_actor_vocab(self) -> Dict[str, Any]:
        """
        Return threat actor vocabulary
        """

        return self.api_get("v4/actor/vocab")
