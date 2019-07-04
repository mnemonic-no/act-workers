#!/usr/bin/env python3

'''Shadowserver ASN worker for the ACT platform

Copyright 2019 the ACT project <opensource@mnemonic.no>

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
import json
import os
import re
import socket
import sqlite3
import sys
import time
import traceback
from ipaddress import AddressValueError, IPv4Address
from logging import debug, error, info, warning
from typing import Dict, Generator, List, Text, Tuple, Union

from RashlyOutlaid.libwhois import ASNRecord, ASNWhois, QueryError

import act.api
from act.api.helpers import handle_fact
from act.workers.libs import worker

CACHE_DIR = worker.get_cache_dir("shadowserver-asn-worker", create=True)
VERSION = "0.1"
ISO_3166_FILE = "https://raw.githubusercontent.com/lukes/" + \
    "ISO-3166-Countries-with-Regional-Codes/master/all/all.json"

# Blacklists of IPs record values
# If value matches blacklist it should not be used
BLACKLIST = {
    "ip": [  # Blacklist IP addresses. Values is IP
        lambda ip: not ip.strip(),                             # Empty values
        lambda ip: ip.strip().lstrip("0").startswith("."),     # IP addreses starting with "0."
        lambda ip: ip == "255.255.255.255",                    # broadcast
        lambda ip: IPv4Address(ip).is_multicast,
        lambda ip: IPv4Address(ip).is_private,
        lambda ip: IPv4Address(ip).is_loopback,
        lambda ip: IPv4Address(ip).is_unspecified,
    ],
    "isp": [  # Blacklist ISPs. Values is asn_record
        lambda asn_record: not asn_record.isp.strip(),         # Exclude Empty values
        lambda asn_record: asn_record.isp == asn_record.cn,    # Exclude values where ISP name == Country Name
        lambda asn_record: asn_record.isp == "AS, {}".format(asn_record.cn),  # Exclude values where ISP name == AS, <CN>
        lambda asn_record: asn_record.isp == ", {}".format(asn_record.cn)     # Exclude values where ISP name == , <CN>
    ],
    "asname": [  # Blacklist ASNAMES. Values is asn_record
        lambda asn_record: not asn_record.asname.strip(),         # Exclude Empty values
    ],
    "cn": [  # Blacklist ASNAMES. Values is asn_record
        lambda asn_record: not asn_record.cn.strip(),         # Exclude Empty values
    ]
}


def get_cn_map(filename: str) -> Dict:
    """
    Read file with county information (ISO 3166 from filename)
    return map with country code (e.g. "NO") as key, and Country
    Name (e.g. "Norway" as value)
    """
    cn_map = {}

    for c_map in json.loads(open(filename, "r", encoding="utf8").read()):
        cn_map[c_map["alpha-2"]] = c_map["name"]

    return cn_map


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Shadowserver ASN enrichment')
    parser.add_argument(
        '--country-codes',
        help="Should point to file downloaded from {}".format(ISO_3166_FILE))

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--bulk', help='bulk query from file. File must contain one IP per line.')
    group.add_argument('--stdin', action='store_true', help='query ip on stdin')
    return parser


def blacklisted(value: Union[ASNRecord, str], blacklist_type: str) -> bool:
    """ Return true if value is blacklisted for the specified type """
    return any([b(value) for b in BLACKLIST[blacklist_type]])  # type: ignore


def get_db_cache(cache_dir: str) -> sqlite3.Connection:
    """
    Open cache and return sqlite3 connection
    Table is created if it does not exists
    """
    cache_file = os.path.join(cache_dir, "cache.sqlite3")
    conn = sqlite3.connect(cache_file)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS asn (
        ip string unique,
        asn int,
        prefix string,
        asname string,
        cn string,
        isp string,
        peers string,
        added int)
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS asn_ip on ASN(ip)")

    return conn


def query_cache(cache: sqlite3.Connection, ip_list: List[str]) -> Generator[Tuple[str, ASNRecord], None, None]:
    """ Query cache for all IPs in list """
    cursor = cache.cursor()

    in_list = ",".join(['"{}"'.format(ip) for ip in ip_list])

    for res in cursor.execute("SELECT * FROM asn WHERE ip in ({})".format(in_list)).fetchall():
        asn_tuple = list(res[1:7])
        asn_tuple[5] = str(asn_tuple[5]).split(",")  # Split peers into list
        yield (res[0], ASNRecord(*asn_tuple))


def add_to_cache(cache: sqlite3.Connection, ip: str, asn_record: ASNRecord) -> None:
    """ ADD IP/ASNRecord to cache """
    cursor = cache.cursor()

    # flatten peer list to comma separated list
    asn_flattened = list(asn_record)
    asn_flattened[5] = ",".join(asn_record.peers)

    cursor.execute("INSERT INTO asn VALUES (?,?,?,?,?,?,?,?)",
                   ([ip] + list(asn_flattened) + [int(time.time())]))
    cache.commit()


def asn_query(ip_list: List[str], cache: sqlite3.Connection) -> Generator[Tuple[str, ASNRecord], None, None]:
    """
    Query shadowserver ASN usingi IP
    Return cached result if the IP is in the cace

    Returns tupe og IP and ASNRecord
    """

    query_ip = set(ip_list)

    for (ip, asn_record) in query_cache(cache, ip_list):
        info("Result from cache: {}".format(asn_record))
        yield (ip, asn_record)
        # Do not query IP, since we found it in cache
        query_ip.remove(ip)

    asnwhois = ASNWhois()
    asnwhois.query = list(query_ip)
    asnwhois.peers = True

    for ip in query_ip:
        try:
            asn_record = asnwhois.result[ip]
        except QueryError:
            error("Query error: {}".format(traceback.format_exc()))
            continue
        except KeyError:
            error("Key error: {}: {}".format(ip, traceback.format_exc()))
            continue
        except socket.timeout:
            error("Socket timeout query shadowserver asn: {} ({}".format(ip, query_ip))
            break  # This will also lead to timeout on all other IPs in this bulk query

        if not asn_record.asn:
            warning("No ASN found for ip {}".format(ip))
            continue

        info("Result from query: {}".format(asn_record))

        add_to_cache(cache, ip, asn_record)

        yield (ip, asn_record)


def handle_ip(
        actapi: act.api.Act,
        cn_map: Dict[str, str],
        ip_list: List[str],
        cache: sqlite3.Connection,
        output_format: Text = "json") -> None:
    """
    Read ip from stdin and query shadowserver - asn.
    if actapi is set, result is added to the ACT platform,
    if not the result is output to stdout.
    """

    ip_query = []

    for ip in ip_list:
        try:
            ip_str = str(IPv4Address(ip))
        except AddressValueError:
            error("Illegal IP address: {}".format(ip))
            continue

        # Exclude blacklisted IPs
        if blacklisted(ip_str, "ip"):
            warning("IP address is blacklisted: {}".format(ip))
        else:
            ip_query.append(ip_str)

    for (ip, res) in asn_query(ip_query, cache):
        # Remove everything after first occurence of "," in isp name
        handle_fact(
            actapi.fact("memberOf", "ipv4Network")
            .source("ipv4", ip)
            .destination("ipv4Network", res.prefix),
            output_format=output_format
        )
        handle_fact(
            actapi.fact("memberOf", "asn")
            .source("ipv4Network", res.prefix)
            .destination("asn", res.asn),
            output_format=output_format
        )

        if blacklisted(res, "asname"):
            debug('asname "{}" for ip {} is blacklisted, skipping'.format(res.asn, ip))
        else:
            handle_fact(actapi.fact("name", res.asname).source("asn", res.asn), output_format=output_format)

        if blacklisted(res, "isp"):
            debug('isp "{}" for ip {} is blacklisted, skipping'.format(res.isp, ip))
        else:
            organization = re.sub(r",.*", "", res.isp).lower()
            handle_fact(
                actapi.fact("owns", "asn")
                .source("organization", organization)
                .destination("asn", res.asn),
                output_format=output_format
            )

            if blacklisted(res, "cn"):
                debug('cn "{}" for ip {} is blacklisted, skipping'.format(res.cn, ip))
            elif res.cn not in cn_map:
                warning('Unknown cn "{}" for ip {}'.format(res.cn, ip))
            else:
                handle_fact(
                    actapi.fact("locatedIn")
                    .source("organization", organization)
                    .destination("country", cn_map[res.cn]),
                    output_format=output_format
                )


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not args.country_codes:
        worker.fatal("You must specify --country-codes on command line or in config file")

    if not os.path.isfile(args.country_codes):
        worker.fatal("Country/region file not found at specified location: {}".format(args.country_codes), 2)

    # Get map of CC -> Country Name
    cn_map = get_cn_map(args.country_codes)

    db_cache = get_db_cache(CACHE_DIR)

    # Read IPs from stdin
    if args.stdin:
        in_data = [ip for ip in sys.stdin.read().split("\n")]
        handle_ip(actapi, cn_map, in_data, db_cache, args.output_format)

    # Bulk lookup
    elif args.bulk:
        all_ips = [ip for ip in open(args.bulk, "r")]
        batch_size = 50
        i = 0
        while i < len(all_ips):
            handle_ip(actapi, cn_map, (all_ips[i:i + batch_size]), db_cache, args.output_format)
            i += batch_size
            time.sleep(1)

    db_cache.close()


def main_log_error() -> None:
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
