#!/usr/bin/env python3

"""Worker module reading domains and ip-addresses from
stdin, writing result in a format understandable by
generic_uploader.py to stdout"""

import argparse
import socket
import sys
import traceback
import ipaddress
from logging import error, warning
from typing import Any, Dict, Generator, Optional, Text

import requests
import urllib3

import act.api
from act.workers.libs import mnemonic, worker

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IPv4 = "IPv4"
IPv6 = "IPv6"
FQDN = "fqdn"


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('PDNS enrichment')
    parser.add_argument('--pdns-baseurl', dest='pdns_baseurl',
                        default="https://api.mnemonic.no/", help="PassiveDNS API host")
    parser.add_argument('--pdns-timeout', dest='timeout', type=int,
                        default=299, help="Timeout")
    parser.add_argument('--pdns-batch-size', dest='pdns_batch_size', type=int,
                        default=100, help="Batch size of pdns queries")
    parser.add_argument('--pdns-apikey', dest='apikey',
                        help="PassiveDNS API key")
    parser.add_argument('--limit', dest='limit', type=int, default=100,
                        help="Maximum number of records to return from pdns")

    return parser


def pdns_query(
        pdns_baseurl: str,
        apikey: str,
        query: str,
        timeout: int,
        proxy_string: Optional[Text] = None,
        batch_size: int = 1000,
        limit: int = 0) -> Generator[Dict[str, Any], None, None]:
    """Query the passivedns result of an address.
    pdns_baseurl - the url to the passivedns api (https://api.mnemonic.no)
    apikey - PassiveDNS API key with the passivedns role (minimum)
    query - string fqdn or ipv4/6
    timeout - default 299 seconds.
    """

    try:
        qmap = {
            "baseurl": pdns_baseurl.strip("/"),
            "query": query
        }

        pdns_url = "{baseurl}/pdns/v3/{query}".format(**qmap)

        if apikey:
            headers = {"Argus-API-Key": apikey}
        else:
            headers = {}

        yield from mnemonic.batch_query(
            "GET",
            pdns_url,
            headers=headers,
            timeout=timeout,
            proxy_string=proxy_string,
            batch_size=batch_size,
            limit=limit)

    except (urllib3.exceptions.ReadTimeoutError,
            requests.exceptions.ReadTimeout,
            socket.timeout) as err:
        warning("Timeout ({0.__class__.__name__}), query: {1}".format(err, query))



def kind(s: Text):
    try:
        ipaddress.IPv4Address(s)
        return IPv4
    except ipaddress.AddressValueError:
        pass
    try:
        ipaddress.IPv6Address(s)
        return IPv6
    except ipaddress.AddressValueError:
        pass
    return FQDN


def process(
        api: act.api.Act,
        pdns_baseurl: str,
        apikey: str,
        timeout: int = 299,
        proxy_string: Optional[Text] = None,
        output_format: Text = "json",
        batch_size: int = 1000,
        limit: int = 0) -> None:
    """Read queries from stdin, resolve each one through passivedns
    printing generic_uploader data to stdout"""

    for query in sys.stdin:
        query = query.strip()
        if not query:
            continue

        i = 0
        for row in pdns_query(
            pdns_baseurl,
            apikey,
            timeout=timeout,
            query=query,
            proxy_string=proxy_string,
            batch_size=batch_size,
            limit=limit):
            rrtype = row["rrtype"]

            i += 1
            if limit == i:
                if kind(query) in (IPv4, IPv6):
                    act.api.helpers.handle_fact(
                        api.fact("excessive", "resolvesTo")
                        .source(*act.api.helpers.ip_obj(row["answer"])),
                        output_format=output_format)
                else:
                    act.api.helpers.handle_fact(
                        api.fact("excessive", "resolvesTo")
                        .source("fqdn", query),
                        output_format=output_format)

            if rrtype in ("a", "aaaa"):
                act.api.helpers.handle_fact(
                    api.fact("resolvesTo")
                    .source("fqdn", row["query"])
                    .destination(*act.api.helpers.ip_obj(row["answer"])),
                    output_format=output_format)

            elif rrtype == "cname":
                act.api.helpers.handle_fact(
                    api.fact("resolvesTo")
                    .source("fqdn", row["query"])
                    .destination("fqdn", row["answer"]),
                    output_format=output_format)

            elif rrtype == "ptr":
                pass  # We do not insert ptr to act
            else:
                warning("Unsupported rrtype: %s: %s" % (rrtype, row))


def main() -> None:
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())
    actapi = worker.init_act(args)

    process(actapi,
            args.pdns_baseurl,
            args.apikey,
            args.timeout,
            args.proxy_string,
            args.output_format,
            args.pdns_batch_size,
            args.limit)


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
