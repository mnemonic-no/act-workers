#!/usr/bin/env python3

"""Worker module reading domains and ip-addresses from
stdin, writing result in a format understandable by
generic_uploader.py to stdout"""

import argparse
import socket
import sys
from logging import warning, error
import traceback
import urllib3
import requests
import act

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RRTYPE_M = {
    "a": {
        "fact_t": "DNSRecord",
        "fact_v": "A",
        "source_t": "fqdn",
        "dest_t": "ipv4"
    },
    "aaaa": {
        "fact_t": "DNSRecord",
        "fact_v": "AAAA",
        "source_t": "fqdn",
        "dest_t": "ipv6"
    },
    "cname": {
        "fact_t": "DNSRecord",
        "fact_v": "CNAME",
        "source_t": "fqdn",
        "dest_t": "fqdn"
    }
}


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='PDNS enrichment')
    parser.add_argument('--proxy-string', dest='proxy_string', default="",
                        help="Proxy to query through")
    parser.add_argument('--pdns-baseurl', dest='pdns_baseurl',
                        default="https://api.mnemonic.no/", help="Argus API host")
    parser.add_argument('--pdns-timeout', dest='timeout', type=int,
                        default=299, help="Timeout")
    parser.add_argument('--pdns-apikey', dest='apikey',
                        help="Argus API key")
    parser.add_argument('--userid', dest='user_id', required=True,
                        help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True,
                        help='ACT API URI')
    parser.add_argument("--logfile", dest="logfile",
                        help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")

    return parser.parse_args()


def batch_query(url, headers=None, timeout=299):
    """ Execute query until we have all results """

    offset = 0
    count = 0

    proxies = {
        'http': ARGS.proxy_string,
        'https': ARGS.proxy_string
    }

    options = {
        "headers": headers,
        "verify": False,
        "timeout": timeout,
        "proxies": proxies,
        "params": {}
    }

    while True:  # do - while offset < count
        options["params"]["offset"] = offset
        req = requests.get(url, **options)

        if not req.status_code == 200:
            errmsg = "status_code: {0.status_code}: {0.content}"
            raise UnknownResult(errmsg.format(req))

        res = req.json()
        data = res["data"]
        count = res.get("count", 0)

        yield from data

        offset += len(data)

        if offset >= count:
            break


def pdns_query(pdns_baseurl, apikey, query, timeout):
    """Query the passivedns result of an address.
    pdns_baseurl - the url to the passivedns api (https://api.mnemonic.no)
    apikey - Argus API key with the passivedns role (minimum)
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

        return batch_query(pdns_url,
                           headers=headers,
                           timeout=timeout)

    except (urllib3.exceptions.ReadTimeoutError,
            requests.exceptions.ReadTimeout,
            socket.timeout) as err:
        error("Timeout ({0.__class__.__name__}), query: {1}".format(
            err, query))


def process(actapi, pdns_baseurl, apikey, timeout=299):
    """Read queries from stdin, resolve each one through passivedns
    printing generic_uploader data to stdout"""

    for query in sys.stdin:
        query = query.strip()
        if not query:
            continue

        for row in pdns_query(pdns_baseurl, apikey, timeout=timeout, query=query):
            rrtype = row["rrtype"]
            query = row["query"]
            answer = row["answer"]

            if rrtype in RRTYPE_M:
                fact = actapi.fact(RRTYPE_M[rrtype]["fact_t"],
                                   RRTYPE_M[rrtype]["fact_v"])
                fact = fact.source(RRTYPE_M[rrtype]["source_t"], query)
                fact = fact.destination(RRTYPE_M[rrtype]["dest_t"], answer)

                fact.add()
            elif rrtype == "ptr":
                pass  # We do not insert ptr to act
            else:
                warning("Unsupported rrtype: %s: %s" % (rrtype, row))


class UnknownResult(Exception):
    """UnknownResult is used in API request (not 200 result)"""

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


if __name__ == '__main__':
    ARGS = parseargs()

    try:
        actapi = act.Act(ARGS.act_baseurl, ARGS.user_id, ARGS.loglevel, ARGS.logfile, "pdns-enrichment")
        process(actapi, ARGS.pdns_baseurl, ARGS.apikey, ARGS.timeout)
    except Exception as e:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise
