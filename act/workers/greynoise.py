#!/usr/bin/env python3

'''greynoise.io worker for the ACT platform

Copyright 2021 the ACT project <opensource@mnemonic.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
'''

import argparse
import contextlib
import sys
import traceback
import warnings
from functools import partialmethod
from logging import error
from typing import Any, Dict, Generator, Optional, Text

import act.api
import requests

from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs('ACT greynoise Client')
    parser.add_argument('--apikey', metavar='KEY',
                        help='greynoise.io community API key')

    return parser


def handle_ip(actapi: act.api.Act, params: Dict[Text, Any], proxies: Optional[Dict[Text, Text]] = None, output_format: Text = "json") -> None:
    """Read IP address from stdin, query greynoise.io community API and
    output a JSON text readable by generic_uploaderr.py"""

    # To figure out what kind of IP address we have, let the ipaddress module
    # parse the string and test for instance type as the platform distinguishes
    # between IPv4 and IPv6 addresses.
    try:
        (ip_type, ip) = act.api.helpers.ip_obj(params.get('ip', ''))
    except ValueError:
        return  # invalid address

    with no_ssl_verification():
        response = requests.get(f"https://api.greynoise.io/v3/community/{params.get('ip', '')}/",
                                headers={'key': params.get('apikey', None),
                                         'Accept': 'application/json'},
                                proxies=proxies)

    data = response.json()

    if data.get('noise'):
        act.api.helpers.handle_fact(actapi.fact('category', data.get('classification', 'noise'))
                                    .source(ip_type, ip),
                                    output_format=output_format)


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not args.apikey:
        worker.fatal("You must specify --apikey on command line or in config file")

    proxies = {
        'http': args.proxy_string,
        'https': args.proxy_string
    } if args.proxy_string else None

    for line in sys.stdin:
        params = {'ip': line.strip(),
                  'apikey': args.apikey}

        handle_ip(actapi, params, proxies, output_format=args.output_format)


@contextlib.contextmanager
def no_ssl_verification() -> Generator[None, None, None]:
    """Monkey patch request to default to no verification of ssl"""

    old_request = requests.Session.request
    requests.Session.request = partialmethod(old_request, verify=False)  # type: ignore

    warnings.filterwarnings('ignore', 'Unverified HTTPS request')
    yield
    warnings.resetwarnings()

    requests.Session.request = old_request  # type: ignore


def main_log_error() -> None:
    """Main entry point, catching and logging errors"""

    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
