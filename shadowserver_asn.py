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
import re
import sys
import time
import traceback
from logging import debug, error, info, warning
from typing import Dict, Union, List

from RashlyOutlaid.libwhois import ASNRecord, ASNWhois, QueryError

import act
import worker
from worker import handle_fact

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
        lambda asn_record: asn_record.isp == "AS, {}".format(asn_record.cn)  # Exclude values where ISP name == AS, <CN>
    ],
    "asname": [  # Blacklist ASNAMES. Values is asn_record
        lambda asn_record: not asn_record.isp.strip(),         # Exclude Empty values
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
    return any([b(value) for b in BLACKLIST[blacklist_type]])


def handle_ip(actapi: act.Act, cn_map: Dict[str, str], ip_list: List[str]) -> None:
    """
    Read ip from stdin and query shadowserver - asn.
    if actapi is set, result is added to the ACT platform,
    if not the result is output to stdout.
    """

    # Filter blacklisted IPs and remove whitespace at beginning and end
    ip_list = [ip.strip() for ip in ip_list if not blacklisted(ip, "ip")]

    asnwhois = ASNWhois()
    asnwhois.query = ip_list
    asnwhois.peers = True

    for ip in ip_list:
        try:
            res = asnwhois.result[ip]
        except QueryError:
            error("Query error: {}".format(traceback.format_exc()))
            continue

        if not res.asn:
            warning("No ASN found for ip {}".format(ip))
            continue

        info(res)

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
                    .destination("location", cn_map[res.cn])
                )


def main() -> None:
    """main function"""

    ARGS = parseargs()
    actapi = act.Act(ARGS.act_baseurl, ARGS.user_id, ARGS.loglevel, ARGS.logfile, "shadowserver-asn")

    # Get map of CC -> Country Name
    cn_map = get_cn_map(ARGS.country_codes)

    # Read IPs from stdin
    if ARGS.stdin:
        in_data = [ip for ip in sys.stdin.read().split("\n")]
        handle_ip(actapi, cn_map, in_data)

    # Bulk lookup
    elif ARGS.bulk:
        all_ips = [ip for ip in open(ARGS.bulk, "r")]
        batch_size = 50
        i = 0
        while i < len(all_ips):
            handle_ip(actapi, cn_map, (all_ips[i:i + batch_size]))
            i += batch_size
            time.sleep(1)


if __name__ == '__main__':

    try:
        main()
    # pylint: disable=broad-except
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        sys.exit(1)
