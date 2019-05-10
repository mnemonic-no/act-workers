""" Argus module to do authenticated requests towards the API and retrive all results """

from typing import Any, Dict, Generator, Optional, Text

import requests

import worker


def batch_query(url: str, headers: Optional[Dict] = None, timeout: int = 299, proxy_string: Optional[Text] = None) -> Generator[Dict[str, Any], None, None]:
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
        options["params"]["offset"] = offset  # type: ignore
        req = requests.get(url, **options)  # type:ignore

        if not req.status_code == 200:
            errmsg = "status_code: {0.status_code}: {0.content}"
            raise worker.UnknownResult(errmsg.format(req))

        res = req.json()
        data = res["data"]
        count = res.get("count", 0)

        yield from data

        offset += len(data)

        if offset >= count:
            break
