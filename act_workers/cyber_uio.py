#!/usr/bin/env python3

'''cyber.uio.no worker for the ACT platform

Copyright 2018 the ACT project <opensource@mnemonic.no>

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


from __future__ import print_function

import argparse
import sys
import traceback
import socket
from logging import error
import urllib3

import requests
import act

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

APIPATH = 'https://cyber.uio.no/api/hashes/{hash}'

VERSION = "{}.{}".format(sum(1 for x in [False, set(), ["Y"], {}, 0] if x), sum(1 for y in [False] if y))


def parse_args():
    """Extract command lines argument"""

    parser = argparse.ArgumentParser(description='ACT cyber.uio.no Client v{}'.format(VERSION))
    parser.add_argument('--proxy', metavar='PROXY', type=str,
                        help='set the system proxy')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--hexdigest', action='store_true',
                       default=False, help='query hexdigestsum on stdin')
    parser.add_argument('--userid', dest='user_id', required=True,
                        help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True,
                        help='ACT API URI')
    parser.add_argument("--logfile", dest="logfile",
                        help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")

    return parser.parse_args()


def handle_hexdigest(actapi, hexdigest, proxy_string=None):
    """Read hexdigest from stdin, query cyber.uio.no and
    output a JSON text readable by generic_uploader.py"""

    if proxy_string:
        proxies = {
            'http': proxy_string,
            'https': proxy_string
        }
    else:
        proxies = None

    try:
        response = requests.get(APIPATH.format(hash=hexdigest), proxies=proxies, verify=False, timeout=120)
    except (urllib3.exceptions.ReadTimeoutError,
            requests.exceptions.ReadTimeout,
            socket.timeout) as err:
        error("Timeout ({0.__class__.__name__}), query: {1}".format(err, response.url))

    if response.text.strip('"').upper() == hexdigest.upper():
        fact = actapi.fact("seenIn")\
            .source("hash", hexdigest)\
            .destination("report", "https://cyber.uio.no/api/hashes")

        fact.add()


def main():
    """main function"""

    args = parse_args()

    actapi = act.Act(args.act_baseurl, args.user_id, args.loglevel, args.logfile, "cyber-uio")

    in_data = sys.stdin.read().strip()

    if args.hexdigest:
        handle_hexdigest(actapi, in_data, args.proxy)


def main_log_error() -> None:
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
