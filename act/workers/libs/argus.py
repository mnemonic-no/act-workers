""" Argus module to do authenticated requests towards the API and retrive all results """

from ipaddress import AddressValueError, IPv4Address
from typing import Any, Dict, Generator, Optional, Text

import requests

import act.api
from act.api.helpers import handle_fact, handle_uri

from . import worker


def is_public_ip(ip_str):
    """ Return True if ip (str) is public """
    try:
        ip = IPv4Address(ip_str)
    except AddressValueError:
        return False

    if IPv4Address(ip).is_multicast \
       or IPv4Address(ip).is_private \
       or IPv4Address(ip).is_loopback \
       or IPv4Address(ip).is_unspecified:
        return False

    return True


def handle_argus_event(actapi: act.api.Act, event: Dict, output_format) -> None:
    properties = event["properties"]

    case_id = event.get("associatedCase", {}).get("id", None)
    uri = event.get("uri")

    if case_id:
        case_id = "ARGUS-{}".format(case_id)
    else:
        # No case
        return

    signature = event["attackInfo"]["signature"]

    if uri:
        handle_uri(actapi, uri, output_format=output_format)
        handle_fact(
            actapi.fact("observedIn").source("uri", uri).destination("incident", case_id),
            output_format=output_format)


def batch_query(
        method: Text,
        url: Text,
        headers: Optional[Dict] = None,
        timeout: int = 299,
        json: Optional[Dict] = None,
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
        options["params"]["offset"] = offset  # type: ignore
        req = requests.request(method, url, json=json, **options)  # type:ignore

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
