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
        proxy_string: Optional[Text] = None,
        batch_size: int = 1000,
        limit: int = 0) -> Generator[Dict[Text, Any], None, None]:
    """ Execute query until we have all results """

    offset = 0
    count = 0

    proxies = {
        'http': proxy_string,
        'https': proxy_string
    }

    if limit and batch_size > limit:
        batch_size = limit

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
            json_params["limit"] = batch_size
        elif method == "GET":
            options["params"]["offset"] = offset  # type: ignore
            options["params"]["limit"] = batch_size

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

        if type(data) != type([]):
            yield data
            break

        yield from data

        debug("count={}".format(count))

        offset += len(data)

        # if we have defined a limit, stop processing on reaching limit
        if limit and offset >= limit:
            break

        if offset >= count:
            break


def single_query(
        method: Text,
        url: Text,
        headers: Optional[Dict] = None,
        timeout: int = 299,
        json_params: Optional[Dict] = None,
        proxy_string: Optional[Text] = None) -> Dict[Text, Any]:
    """ Execute query for single result, returns result """

    try:
        for res in batch_query(method, url, headers, timeout, json_params, proxy_string):
            return res
    except worker.UnknownResult as e:
        if not str(e).startswith("Unknown error: 404"):
            raise

    raise worker.NoResult()
