#!/usr/bin/env python3

"""ip->asn history worker for the ACT platform

Copyright 2019 mnemonic AS <opensource@mnemonic.no>

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
"""


import sys
import traceback
from logging import error
from typing import List, Optional, Text, Tuple

import act.api
import requests
from act.api.libs import cli

import act
from act.workers.libs import worker

WORKER_NAME = "ip-asn-history"


def lookup_ip(ip: Text, proxy: Optional[Text] = None) -> List[Tuple[Text, Text]]:
    """Lookup historc ASN registration for an IP against the CIRCL online ASN database"""

    proxies = {"http": proxy, "https": proxy} if proxy else None

    r = requests.get(
        "https://bgpranking-ng.circl.lu/ipasn_history/?ip={}".format(ip),
        proxies=proxies,
    )

    data = r.json()

    return [(x["asn"], x["prefix"]) for x in data["response"].values()]


def process(api: act.api.Act, proxy=None, output_format: Text = "json") -> None:
    """Read queries from stdin"""

    for query in sys.stdin:
        query = query.strip()

        if not query:
            continue

        for asn, network in lookup_ip(query, proxy):
            act.api.helpers.handle_fact(
                api.fact("memberOf")
                .source("ipv4", query)
                .destination("ipv4Network", network),
                output_format=output_format,
            )

            act.api.helpers.handle_fact(
                api.fact("memberOf")
                .source("ipv4Network", network)
                .destination("asn", asn),
                output_format=output_format,
            )


def main() -> None:
    """Main function"""
    # Look for default ini file in "/etc/actworkers.ini" and
    # ~/config/actworkers/actworkers.ini (or replace .config with
    # $XDG_CONFIG_DIR if set)
    args = cli.handle_args(worker.parseargs(WORKER_NAME))
    actapi = worker.init_act(args)

    process(actapi, args.proxy_string, args.output_format)


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
