#!/usr/bin/env python3

"""Worker module reading domains and ip-addresses from
stdin, writing result in a format understandable by
generic_uploader.py to stdout"""

import argparse
import socket
import sys
import traceback
from logging import error, warning
from typing import Any, Dict, Generator, Optional, Text

import requests
import urllib3

import act.api
from act.workers.libs import argus, worker

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('ARGUS Case enrichment')
    parser.add_argument('--argus-baseurl', dest='argus_baseurl',
                        default="https://api.mnemonic.no/", help="Argus API host")
    parser.add_argument('--argus-timeout', dest='timeout', type=int,
                        default=300, help="Timeout")
    parser.add_argument('--argus-apikey', dest='apikey',
                        help="Argus API key")

    return parser


def event_case_query(
        argus_baseurl: str,
        apikey: str,
        timeout: int,
        proxy_string: Optional[Text] = None) -> Generator[Dict[str, Any], None, None]:
    """Query the passivedns result of an address.
    argus_baseurl - the url to the passivedns api (https://api.mnemonic.no)
    apikey - Argus API key with the passivedns role (minimum)
    timeout - timeout towards API
    """

    limit = 2000

    try:
        qmap = {
            "baseurl": argus_baseurl.strip("/"),
            "lastUpdatedTimestamp": last_update,
            "startTimestamp": start_time,
            "sortBy": ["lastUpdated"],
            "limit": limit
        }

        argus_url = "{baseurl}/events/v1/{query}".format(**qmap)

        if apikey:
            headers = {"Argus-API-Key": apikey}
        else:
            headers = {}

        yield from argus.batch_query(
            argus_url,
            headers=headers,
            timeout=timeout,
            proxy_string=proxy_string)

    except (urllib3.exceptions.ReadTimeoutError,
            requests.exceptions.ReadTimeout,
            socket.timeout) as err:
        error("Timeout ({0.__class__.__name__}), query: {1}".format(err, query))


def process(
        api: act.api.Act,
        argus_baseurl: str,
        apikey: str,
        timeout: int = 299,
        proxy_string: Optional[Text] = None,
        output_format: Text = "json") -> None:
    """Read queries from stdin, resolve each one through passivedns
    printing generic_uploader data to stdout"""

    for row in argus_query(argus_baseurl, apikey, timeout=timeout, query=query, proxy_string=proxy_string):
        print(row)


def main() -> None:
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    auth = None
    if args.http_user:
        auth = (args.http_user, args.http_password)

    actapi = act.api.Act(
        args.act_baseurl,
        args.user_id,
        args.loglevel,
        args.logfile,
        worker.worker_name(),
        requests_common_kwargs={'auth': auth})

    process(
        actapi,
        args.argus_baseurl,
        args.apikey,
        args.timeout,
        args.proxy_string,
        args.output_format)


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
