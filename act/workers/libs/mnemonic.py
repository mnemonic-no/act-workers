""" Common functions towards mnemonic API """

from logging import debug, error
from typing import Any, Dict, Generator, Optional, Text

import requests

from . import worker


def batch_query(
        method: Text,
        url: Text,
        headers: Optional[Dict] = None,
        timeout: int = 299,
        json_params: Optional[Dict] = None,
        proxy_string: Optional[Text] = None) -> Generator[Dict[Text, Any], None, None]:
    """ Execute query until we have all results """

    offset = 0
    count = 0

    proxies = {
        'http': proxy_string,
        'https': proxy_string
    }

    options = {
        "headers": headers,
        "verify": False,
        "timeout": timeout,
        "proxies": proxies,
        "params": {}
    }

    while True:  # do - while offset < count
        # ARGUS uses offset in body for POST requests and request parameters for GET requests

        if method == "POST" and json_params:
            json_params["offset"] = offset
        elif method == "GET":
            options["params"]["offset"] = offset  # type: ignore

        debug("Executing search: {}, json={}, options={}".format(url, json_params, options))
        req = requests.request(method, url, json=json_params, **options)  # type:ignore

        try:
            res = req.json()
        except ValueError:
            raise worker.UnknownResult("Illegal JSON, {}, {}".format(req, req.content))

        if req.status_code == 402:
            if any([msg.get("message") == "Resource limit exceeded" for msg in res.get("messages")]):
                error("Resource limit exceeded: {}".format(res))
                return
            raise worker.UnknownResult("Unknown 402: {}".format(req.content))

        if not req.status_code == 200:
            raise worker.UnknownResult("Unknown error: {}, {}".format(req, req.content))

        data = res["data"]
        count = res.get("count", 0)

        yield from data

        debug("count={}".format(count))

        offset += len(data)

        if offset >= count:
            break
