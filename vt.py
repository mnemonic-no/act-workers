#!/usr/bin/env python3

'''VirusTotal worker for the ACT platform

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

requirements:

    https://github.com/blacktop/virustotal-api

    pip install virustotal-api
'''

import argparse
import collections
import contextlib
import ipaddress
import re
import sys
import logging
import warnings
from logging import error
import traceback
import urllib.parse
from typing import List
import os
import act
from functools import partialmethod
from typing import Optional, Text, Generator

import requests
from virus_total_apis import PublicApi as VirusTotalApi

EXCLUDED_MALWARE_NAMES = ['trojan', 'malware', 'generic']

AV_HEURISTICS = ['trojan', 'adware', 'dropper', 'miner',
                 'backdoor', 'malware', 'downloader', 'rat',
                 'hacktool', 'ransomware', 'cryptolocker',
                 'banker', 'financial', 'eicar', 'scanner']

ADWARE_OVERRIDES = ['opencandy', 'monetize', 'adload', 'somoto']

MS_RE = re.compile(r"(.*?):(.*?)\/(?:([^!.]+))?(?:[!.](\w+))?")
KASPERSKY_RE = re.compile(r"((.+?):)?(.+?)\.(.+?)\.([^.]+)(\.(.+))?")
VERSION = "{}.{}".format(sum(1 for x in [False, set(), ["Y"], {}, 0] if x), sum(1 for y in [False] if y))


def parse_args() -> argparse.Namespace:
    """Extract command lines argument"""

    parser = argparse.ArgumentParser(description='ACT VT Client v{}'.format(VERSION))
    parser.add_argument('--apikey', metavar='KEY', type=str,
                        required=True, help='VirusTotal API key')
    parser.add_argument('--proxy', metavar='PROXY', type=str,
                        help='set the system proxy')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--hexdigest', action='store_true',
                       default=False, help='query hexdigestsum on stdin')
    group.add_argument('--ip', action='store_true',
                       default=False, help='query ip on stdin')
    group.add_argument('--domain', action='store_true',
                       default=False, help='query domain on stdin')

    parser.add_argument('--userid', dest='user_id', required=True,
                        help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True,
                        help='ACT API URI')
    parser.add_argument("--logfile", dest="logfile",
                        help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")
    parser.add_argument('--http_user', dest='http_user',  help="HTTP Basic Auth user")
    parser.add_argument('--http_password', dest='http_password', help="HTTP Basic Auth password")

    return parser.parse_args()


def name_extraction(engine: Text, body: dict) -> Optional[Text]:
    """Extract the name from certain AV engines based on regular
    expression matching"""

    if engine == "Microsoft":
        match = MS_RE.match(body["result"])
        if match:
            return match.groups()[2].lower()

    if engine == "Kaspersky":
        match = KASPERSKY_RE.match(body["result"])
        if match:
            return match.groups()[4].lower()

    return None


def is_adware(text: Text) -> bool:
    """Test for adware signature using heuristics in ADWARE_OVERRIDES"""

    for adware_override in ADWARE_OVERRIDES:
        if adware_override in text:
            return True
    return False


def handle_hexdigest(actapi: act.Act, vtapi: VirusTotalApi, hexdigest: Text, cache: dict={}) -> None:
    """Read hexdigest from stdin, query VirusTotal and
    output a JSON text readable by generic_uploader.py"""

    if hexdigest in cache:
        return

    cache['hexdigest'] = True

    names = set()
    kind: collections.Counter = collections.Counter()
    with no_ssl_verification():
        response = vtapi.get_file_report(hexdigest)

    if 'scans' not in response['results']:
        # VirusTotal has not seend this hexdigest before
        return

    for engine, body in response['results']['scans'].items():
        if not body['detected']:
            continue

        name = name_extraction(engine, body)
        if name and name not in EXCLUDED_MALWARE_NAMES:
            names.add(name)

        res = body['result'].lower()

        if is_adware(res):
            names.add('adware')

        for heur in AV_HEURISTICS:
            if heur in res:
                # Add a vote for this heuristic
                kind[heur] += 1

    # Decide on malware "kind" based on popular vote among the
    # names extracted from the AV_HEURISTICS.
    if kind:
        names.add(kind.most_common()[0][0])

    results = response['results']
    content_id = results['sha256']
    for hash in ['sha1', 'sha256', 'md5']:
        act.helpers.handle_fact(actapi.fact('represents', 'vt')\
                                .source('hash', results[hash])\
                                .destination('content', content_id))
                                

    for name in names:
        act.helpers.handle_fact(actapi.fact('classifiedAs', 'vt')
            .source('content', content_id)\
            .destination('tool', name))

    if 'detected_urls' in results:
        for u in map(urllib.parse.urlparse, [x['url'] for x in results['detected_urls']]):
            my_uri = add_uri(actapi, 'fqdn', u.netloc, list(u))
            act.helpers.handle_fact(actapi.fact('at', 'vt')\
                .source('content', content_id)\
                .destination('uri', my_uri))
    if 'undetected_urls' in results:
        for u in map(urllib.parse.urlparse, [x[0] for x in results['undetected_urls']]):
            my_uri = add_uri(actapi, 'fqdn', u.netloc, list(u))
            act.helpers.handle_fact(actapi.fact('at', 'vt')\
                .source('content', content_id)\
                .destination('uri', my_uri))


def handle_ip(actapi: act.Act, vtapi: VirusTotalApi, ip: Text) -> None:
    """Read IP address from stdin, query VirusTotal and
    output a JSON text readable by generic_uploaderr.py"""

    # To figure out what kind of IP address we have, let the ipaddress module
    # parse the string and test for instance type as the platform distinguishes
    # between IPv4 and IPv6 addresses.
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError as err:
        return  # invalid address

    if isinstance(ip_address, ipaddress.IPv4Address):
        ip_type = 'ipv4'
    elif isinstance(ip_address, ipaddress.IPv6Address):
        ip_type = 'ipv6'
    else:
        return  # if it is an unknown type, abort early. No query will happen.

    with no_ssl_verification():
        response = vtapi.get_ip_report(ip)

    try:
        results = response['results']
    except KeyError:
        logging.error("%s in handle_ip for %s", response, ip)
        sys.exit(1)

    # create a dictionary of url that is observed in relation to the address.
    urls: collections.defaultdict = collections.defaultdict(list)
    if 'detected_urls' in results:
        for u in map(urllib.parse.urlparse, [x['url'] for x in results['detected_urls']]):
            urls[u.netloc].append(u)
    if 'undetected_urls' in results:
        for u in map(urllib.parse.urlparse, [x[0] for x in results['undetected_urls']]):
            urls[u.netloc].append(u)

    if 'resolutions' in results:
        for resolution in results['resolutions']:
            act.helpers.handle_fact(actapi.fact('resolvesTo')\
                .source('fqdn', resolution['hostname'])\
                .destination(ip_type, ip))
            # add all detected and undetected urls related to a given resolved hostname
            if resolution['hostname'] in urls:
                for u in urls[resolution['hostname']]:
                    add_uri(actapi, 'fqdn', resolution['hostname'], list(u))
    # if the actuall ip is part of the url, add the urls directly connected to the
    # ip.
    if ip in urls:
        for u in urls[ip]:
            add_uri(actapi, ip_type, ip, list(u))

    if 'detected_downloaded_samples' in results:
        for sample in results['detected_downloaded_samples']:

            my_uri = add_uri(actapi, ip_type, ip, ['network', ip, '', '', '', ''])

            act.helpers.handle_fact(actapi.fact('at')\
                .source('content', sample['sha256'])\
                .destination('uri', my_uri))

            act.helpers.handle_fact(actapi.fact('represents')\
                .source('hash', sample['sha256'])\
                .destination('content', sample['sha256']))

            handle_hexdigest(actapi, vtapi, sample['sha256'])

    if 'detected_communicating_samples' in results:
        for sample in results['detected_communicating_samples']:
            my_uri = add_uri(actapi, ip_type, ip, ['network', ip, '', '', '', ''])

            act.helpers.handle_fact(actapi.fact('connectsTo', ip_type)\
                .source('content', sample['sha256'])\
                .destination('uri', my_uri))

            act.helpers.handle_fact(actapi.fact('represents')\
                .source('hash', sample['sha256'])\
                .destination('content', sample['sha256']))

            handle_hexdigest(actapi, vtapi, sample['sha256'])


def add_uri(actapi: act.Act,
            addr_type: str,
            addr: str,
            url: List[str],
            cache: dict={}) -> str:
    """Add a URI to the platform by creating the componentOf and scheme facts
If called multiple times with arguments creating the same URI, the facts will only sent once.
Return: The URI added
"""
    try:
        my_uri = str(urllib.parse.urlunparse(url))
        if my_uri in cache:
            return my_uri

        cache[my_uri] = True

        act.helpers.handle_fact(actapi.fact("componentOf")\
              .source(addr_type, addr)\
              .destination("uri", my_uri))

        act.helpers.handle_fact(actapi.fact("scheme", url[0])\
              .source("uri", my_uri))

        if url[2]:  # path
            act.helpers.handle_fact(actapi.fact("componentOf")\
                  .source("path", url[2])\
                  .destination("uri", my_uri))

            basename = os.path.basename(url[2])
            if basename.strip():
                act.helpers.handle_fact(actapi.fact("componentOf")\
                      .source("path", basename)\
                      .destination("uri", my_uri))

        if url[3]:  # query
            act.helpers.handle_fact(actapi.fact("componentOf")\
                  .source("query", url[3])\
                  .destination("uri", my_uri))

    except act.base.ResponseError as e:
        sys.stderr.write(str(e))

    return my_uri


def handle_domain(actapi: act.Act, vtapi: VirusTotalApi, domain: Text) -> None:
    """Read IP address from stdin, query VirusTotal and
    output a JSON text readable by generic_uploaderr.py"""

    with no_ssl_verification():
        response = vtapi.get_domain_report(domain)

    try:
        results = response['results']
    except KeyError:
        logging.error("%s in handle_domain for %s", response, domain)
        sys.exit(1)

    if 'detected_urls' in results:
        for u in map(urllib.parse.urlparse, [x['url'] for x in results['detected_urls']]):
            add_uri(actapi, 'fqdn', domain, list(u))
    if 'undetected_urls' in results:
        for u in map(urllib.parse.urlparse, [x[0] for x in results['undetected_urls']]):
            add_uri(actapi, 'fqdn', domain, list(u))

    if 'resolutions' in results:
        for resolution in results['resolutions']:
            ip = resolution['ip_address']
            # To figure out what kind of IP address we have, let the ipaddress module
            # parse the string and test for instance type as the platform distinguishes
            # between IPv4 and IPv6 addresses.
            try:
                ip_address = ipaddress.ip_address(ip)
            except ValueError as err:
                continue  # invalid address

            if isinstance(ip_address, ipaddress.IPv4Address):
                ip_type = 'ipv4'
            elif isinstance(ip_address, ipaddress.IPv6Address):
                ip_type = 'ipv6'
            else:
                continue  # if it is an unknown type, abort early. No query will happen.

            act.helpers.handle_fact(actapi.fact('resolvesTo')\
                .source('fqdn', domain)\
                .destination(ip_type, ip))

    if 'detected_downloaded_samples' in results:
        for sample in results['detected_downloaded_samples']:
            my_uri = add_uri(actapi, 'fqdn', domain, ['network', domain, '', '', '', ''])
            act.helpers.handle_fact(actapi.fact('at')\
                .source('content', sample['sha256'])\
                .destination('uri', my_uri))
            act.helpers.handle_fact(actapi.fact('represents')\
                .source('hash', sample['sha256'])\
                .destination('content', sample['sha256']))
            handle_hexdigest(actapi, vtapi, sample['sha256'])

    if 'detected_communicating_samples' in results:
        for sample in results['detected_communicating_samples']:
            my_uri = add_uri(actapi, 'fqdn', domain, ['network', domain, '', '', '', ''])
            act.helpers.handle_fact(actapi.fact('connectsTo')\
                .source('content', sample['sha256'])\
                .destination('uri', my_uri))
            act.helpers.handle_fact(actapi.fact('represents')\
                .source('hash', sample['sha256'])\
                .destination('content', sample['sha256']))
            handle_hexdigest(actapi, vtapi, sample['sha256'])


def main() -> None:
    """main function"""

    args = parse_args()

    auth = None
    if args.http_user:
        auth = (args.http_user, args.http_password)

    actapi = act.Act(args.act_baseurl, args.user_id, args.loglevel, args.logfile, "vt-enrichment", requests_common_kwargs={'auth': auth})

    in_data = sys.stdin.read().strip()

    proxies = {
        'http': args.proxy,
        'https': args.proxy
    } if args.proxy else None

    vtapi = VirusTotalApi(args.apikey, proxies=proxies)

    if args.hexdigest:
        handle_hexdigest(actapi, vtapi, in_data)

    if args.ip:
        handle_ip(actapi, vtapi, in_data)

    if args.domain:
        handle_domain(actapi, vtapi, in_data)


@contextlib.contextmanager
def no_ssl_verification() -> Generator[None, None, None]:
    """Monkey patch request to default to no verification of ssl"""

    old_request = requests.Session.request
    requests.Session.request = partialmethod(old_request, verify=False)  # type: ignore

    warnings.filterwarnings('ignore', 'Unverified HTTPS request')
    yield
    warnings.resetwarnings()

    requests.Session.request = old_request  # type: ignore


if __name__ == '__main__':

    try:
        main()
    except Exception as e:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise
