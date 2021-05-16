#!/usr/bin/env python3

'''abuseipdb worker for the ACT platform

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
from typing import Text, Dict, Optional, Any, Generator

import requests

import act.api
from act.workers.libs import worker

CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs('ACT abuseipdb Client')
    parser.add_argument('--apikey', metavar='KEY',
                        help='abuseipdb API key')
    parser.add_argument('--max-age-in-days', default=90, type=int,
                        help='Max age of reports in abuseipdb database')

    return parser


def handle_ip(actapi: act.api.Act, params: Dict[Text, Any], proxies: Optional[Dict[Text, Text]] = None, output_format: Text = "json") -> None:
    """Read IP address from stdin, query abuseipdb and
    output a JSON text readable by generic_uploaderr.py"""

    # To figure out what kind of IP address we have, let the ipaddress module
    # parse the string and test for instance type as the platform distinguishes
    # between IPv4 and IPv6 addresses.
    try:
        (ip_type, ip) = act.api.helpers.ip_obj(params.get('ip', ''))
    except ValueError:
        return  # invalid address

    with no_ssl_verification():
        response = requests.get("https://api.abuseipdb.com/api/v2/check",
                                params=[('ipAddress', params.get('ip', "")),
                                        ('maxAgeInDays', params.get('maxAgeInDays', 90)),
                                        ('verbose', True)],
                                headers={'Key': params.get('apikey', None),
                                         'Accept': 'application/json'},
                                proxies=proxies)

    data = response.json()

    if 'data' in data and 'reports' in data['data']:
        for report in data['data']['reports']:
            for category in report.get('categories', []):
                act.api.helpers.handle_fact(actapi.fact('category', CATEGORIES[category])
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
        params = {'maxAgeInDays': args.max_age_in_days,
                  'ip': line.strip(),
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
