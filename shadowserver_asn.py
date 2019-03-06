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
import sqlite3
import sys
import time
import traceback
from logging import debug, error, info, warning
from typing import Dict, Generator, List, Tuple, Union

from RashlyOutlaid.libwhois import ASNRecord, ASNWhois, QueryError

import act
import worker
from worker import handle_fact

CACHE_DIR = worker.get_cache_dir("shadowserver-asn-worker", create=True)
VERSION = "0.1"
ISO_3166_FILE = "https://raw.githubusercontent.com/lukes/" + \
    "ISO-3166-Countries-with-Regional-Codes/master/all/all.json"

# Blacklists of IPs record values
# If value matches blacklist it should not be used
BLACKLIST = {
    "ip": [  # Blacklist IP addresses. Values is IP
        lambda ip: not ip.strip(),                             # Empty values
        lambda ip: ip.strip().lstrip("0").startswith(".")      # IP addreses starting with "0."
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

    for c_map in json.loads(open(filename, "r").read()):
        cn_map[c_map["alpha-2"]] = c_map["name"]

    return cn_map


def parseargs() -> argparse.Namespace:
    """ Parse arguments """
    parser = worker.parseargs('Shadowserver ASN enrichment')
    parser.add_argument(
        '--country-codes',
        required=True,
        help="Should point to file downloaded from {}".format(ISO_3166_FILE))

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--bulk', help='bulk query from file. File must contain one IP per line.')
    group.add_argument('--stdin', action='store_true', help='query ip on stdin')
    return parser.parse_args()


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

        if not asn_record.asn:
            warning("No ASN found for ip {}".format(ip))
            continue

        info("Result from query: {}".format(asn_record))

        add_to_cache(cache, ip, asn_record)

        yield (ip, asn_record)


def handle_ip(actapi: act.Act, cn_map: Dict[str, str], ip_list: List[str], cache: sqlite3.Connection) -> None:
    """
    Read ip from stdin and query shadowserver - asn.
    if actapi is set, result is added to the ACT platform,
    if not the result is output to stdout.
    """

    # Filter blacklisted IPs and remove whitespace at beginning and end
    ip_list = [ip.strip() for ip in ip_list if not blacklisted(ip, "ip")]

    for (ip, res) in asn_query(ip_list, cache):
        # Remove everything after first occurence of "," in isp name
        handle_fact(
            actapi.fact("memberOf", "ipv4Network")
            .source("ipv4", ip)
            .destination("ipv4Network", res.prefix)
        )
        handle_fact(
            actapi.fact("memberOf", "asn")
            .source("ipv4Network", res.prefix)
            .destination("asn", res.asn)
        )

        if blacklisted(res, "asname"):
            debug('asname "{}" for ip {} is blacklisted, skipping'.format(res.asn, ip))
        else:
            handle_fact(actapi.fact("name", res.asname).source("asn", res.asn))

        if blacklisted(res, "isp"):
            debug('isp "{}" for ip {} is blacklisted, skipping'.format(res.isp, ip))
        else:
            organization = re.sub(r",.*", "", res.isp).lower()
            handle_fact(
                actapi.fact("owns", "asn")
                .source("organization", organization)
                .destination("asn", res.asn)
            )

            if blacklisted(res, "cn"):
                debug('cn "{}" for ip {} is blacklisted, skipping'.format(res.cn, ip))
            elif res.cn not in cn_map:
                warning('Unknown cn "{}" for ip {}'.format(res.cn, ip))
            else:
                handle_fact(
                    actapi.fact("locatedIn")
                    .source("organization", organization)
                    .destination("country", cn_map[res.cn])
                )


def main() -> None:
    """main function"""

    ARGS = parseargs()
    actapi = act.Act(ARGS.act_baseurl, ARGS.user_id, ARGS.loglevel, ARGS.logfile, "shadowserver-asn")

    # Get map of CC -> Country Name
    cn_map = get_cn_map(ARGS.country_codes)

    db_cache = get_db_cache(CACHE_DIR)

    # Read IPs from stdin
    if ARGS.stdin:
        in_data = [ip for ip in sys.stdin.read().split("\n")]
        handle_ip(actapi, cn_map, in_data, db_cache)

    # Bulk lookup
    elif ARGS.bulk:
        all_ips = [ip for ip in open(ARGS.bulk, "r")]
        batch_size = 50
        i = 0
        while i < len(all_ips):
            handle_ip(actapi, cn_map, (all_ips[i:i + batch_size]), db_cache)
            i += batch_size
            time.sleep(1)

    db_cache.close()


if __name__ == '__main__':

    try:
        main()
    # pylint: disable=broad-except
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        sys.exit(1)