""" Common functions towards mnemonic API """

from logging import debug
from typing import Any, Callable, Dict, Generator, Optional, Text, cast

import requests

from . import worker

# Mapping of messages and message templates provided in errors from backend to
# Exceptions that will be raised

STATUS_CODE_TEMPLATES: Dict[int, Dict[Text, Callable[[Dict[Text, Any]], Exception]]] = {
    402: {
        "resource.limit.exceeded": lambda msg: worker.ResourceLimitExceeded(
            "{message}".format(**msg)
        ),
    },
    412: {
        "This query is not allowed": lambda msg: worker.NotAllowed(
            "{message}".format(**msg)
        ),
    },
    503: {
        "service.timeout": lambda msg: worker.ServiceTimeout(
            "{message} ({field}={parameter})".format(**msg)
        ),
    },
}


def status_code_handler(req: requests.models.Response, res: Dict[Text, Any]) -> None:
    """

    Status Code Handler for non-200 status codes
    Raise exceptions on combinations of status code and message

    Arguments:

    req: requests Response object
    res: requests Response content json parsed

    """

    if req.status_code == 401:
        raise worker.AuthenticationError

    if req.status_code == 404:
        raise worker.NoResult

    if req.status_code in STATUS_CODE_TEMPLATES:
        # Example output on Timeout:
        # {"responseCode":503,"limit":0,"offset":0,"count":0,"metaData":{},"messages":[{"message":null,"messageTemplate":null,"type":"ACTION_ERROR","field":null,"parameter":null,"timestamp":1606137003885},{"message":"Request timed out, service may be overloaded or unavailable","messageTemplate":"service.timeout","type":"ACTION_ERROR","field":null,"parameter":null,"timestamp":1606137003993}],"data":null,"size":0}

        for message in res["messages"]:
            msg_template = message.get("messageTemplate")
            msg = message.get("message")
            match_error = cast(Dict[Text, Any], STATUS_CODE_TEMPLATES[req.status_code])

            # search for text both in message and messageTemplate
            if msg_template in match_error:
                raise STATUS_CODE_TEMPLATES[req.status_code][msg_template](message)
            if msg in match_error:
                raise STATUS_CODE_TEMPLATES[req.status_code][msg](message)

    raise worker.FetchError(f"Unknown error: {req}, {req.text}")


def batch_query(
    method: Text,
    url: Text,
    headers: Optional[Dict[Text, Any]] = None,
    timeout: int = 299,
    json_params: Optional[Dict[Text, Any]] = None,
    proxy_string: Optional[Text] = None,
    batch_size: int = 1000,
    limit: int = 0,
) -> Generator[Dict[Text, Any], None, None]:
    """Execute query until we have all results"""

    offset = 0
    count = 0

    proxies = {"http": proxy_string, "https": proxy_string}

    if limit and batch_size > limit:
        batch_size = limit

    options: Dict[Text, Any] = {
        "headers": headers,
        "verify": False,
        "timeout": timeout,
        "proxies": proxies,
        "params": {},
    }

    while True:  # do - while offset < count
        # ARGUS uses offset in body for POST requests and request parameters for GET requests

        if method == "POST" and json_params:
            json_params["offset"] = offset
            json_params["limit"] = batch_size
        elif method == "GET":
            options["params"]["offset"] = offset
            options["params"]["limit"] = batch_size

        debug(
            "Executing search: {}, json={}, options={}".format(
                url, json_params, options
            )
        )
        req = requests.request(method, url, json=json_params, **options)

        try:
            res = req.json()
        except ValueError:
            raise worker.FetchError(f"Illegal JSON, {req}, {req.text}")

        if req.status_code != 200:
            status_code_handler(req, res)

        data = res["data"]
        count = res.get("count", 0)

        if not isinstance(data, list):
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
    headers: Optional[Dict[Text, Any]] = None,
    timeout: int = 299,
    json_params: Optional[Dict[Text, Any]] = None,
    proxy_string: Optional[Text] = None,
) -> Dict[Text, Any]:
    """Execute query for single result, returns result"""

    try:
        for res in batch_query(
            method, url, headers, timeout, json_params, proxy_string
        ):
            return res
    except worker.FetchError as e:
        if not str(e).startswith("Unknown error: 404"):
            raise

    raise worker.NoResult()
