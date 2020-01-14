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
import logging
import os
import re
import sys
import traceback
import urllib.parse
import warnings
from functools import partialmethod
from logging import error, info
from typing import Generator, List, Optional, Text, Tuple, Set

import requests

import act.api
from act.workers.libs import worker
from virus_total_apis import PublicApi as VirusTotalApi

ADWARE_OVERRIDES = ['opencandy', 'monetize', 'adload', 'somoto']

HASH_RE = re.compile(r'^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$')

# Type:Platform/Family.Variant!Suffixes
MS_RE = re.compile(r"(.*?):(.*?)\/(?:([^!.]+))?(?:[!.](\w+))?")

# [Prefix:]Behaviour.Platform.Name[.Variant]
KASPERSKY_RE = re.compile(r"((.+?):)?(.+?)\.(.+?)\.([^.]+)(\.(.+))?")

# Extract CVE
CVE_RE = re.compile(r"(CVE-\d+-\d+)")

# <Threat Type>.<Platform>.<Malware Family>.<Variant>.<Other info*>
# *Optional
TREND_RE = re.compile(r"(.+?)\.(.+?)\.(.+?)\.(.+?)(\.(.+))?")


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs('ACT VT Client')
    parser.add_argument('--apikey', metavar='KEY',
                        help='VirusTotal API key')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--hexdigest',
        action='store_true',
        default=False,
        help='Skip autodetection of type and force lookup as hexdigest')
    group.add_argument(
        '--ip',
        action='store_true',
        default=False,
        help='Skip autodetection of type and force lookup as IP address')
    group.add_argument(
        '--domain',
        action='store_true',
        default=False,
        help='Skip autodetection of type and force lookup as domain')

    return parser


def name_extraction(engine: Text, body: dict) -> Optional[Tuple[Text, Optional[Text]]]:
    """Extract the name from certain AV engines based on regular
    expression matching"""

    if engine == "Microsoft":
        match = MS_RE.match(body["result"])
        if match:
            return match.groups()[2].lower(), match.groups()[0].lower()

    if engine == "Kaspersky":
        match = KASPERSKY_RE.match(body["result"])
        if match:
            # Kaspersky does not allways include toolType in the naming scheme
            if match.groups()[1]:
                # Extract field 1 (inner match group) as field 0 (outer match group)
                # contains the ending ':'
                toolType: Optional[Text] = match.groups()[1].lower()
            else:
                toolType = None
            return match.groups()[4].lower(), toolType

    if engine == "TrendMicro":
        match = TREND_RE.match(body["result"])
        if match:
            return match.groups()[2].lower(), match.groups()[0].lower()

    return None


def cve_extraction(body: dict) -> Set[Text]:
    """Extract any CVE names"""

    return {cve.lower() for cve in CVE_RE.findall(body['result'])}


def is_adware(text: Text) -> bool:
    """Test for adware signature using heuristics in ADWARE_OVERRIDES"""

    for adware_override in ADWARE_OVERRIDES:
        if adware_override in text:
            return True
    return False


def handle_hexdigest(
        actapi: act.api.Act,
        vtapi: VirusTotalApi,
        hexdigest: Text,
        cache: dict = {},
        output_format: Text = "json") -> None:
    """Read hexdigest from stdin, query VirusTotal and
    output a JSON text readable by generic_uploader.py"""

    if hexdigest in cache:
        return

    cache['hexdigest'] = True

    names: Set[Tuple[Text, Optional[Text]]] = set()
    cves: Set[Text] = set()

    with no_ssl_verification():
        response = vtapi.get_file_report(hexdigest)

    if 'scans' not in response['results']:
        # VirusTotal has not seend this hexdigest before
        return

    for engine, body in response['results']['scans'].items():
        if not body['detected']:
            continue

        cves.update(cve_extraction(body))

        ext_res = name_extraction(engine, body)
        if ext_res:
            names.add((ext_res[0], ext_res[1]))

        res = body['result'].lower()

        if is_adware(res):
            names.add(('adware', 'adware'))

    results = response['results']
    content_id = results['sha256']
    for myhash in ['sha1', 'sha256', 'md5']:
        act.api.helpers.handle_fact(actapi.fact('represents')
                                    .source('hash', results[myhash])
                                    .destination('content', content_id),
                                    output_format=output_format)

    for cve in cves:
        act.api.helpers.handle_fact(actapi.fact('exploits')
                                    .source('content', content_id)
                                    .destination('vulnerability', cve),
                                    output_format=output_format)

    for name, toolType in names:
        act.api.helpers.handle_fact(actapi.fact('classifiedAs')
                                    .source('content', content_id)
                                    .destination('tool', name),
                                    output_format=output_format)

        # toolType may be None (as not all nameing schemes include toolType)
        if toolType:
            act.api.helpers.handle_fact(actapi.fact('classifiedAs')
                                        .source('tool', name)
                                        .destination('toolType', toolType),
                                        output_format=output_format)

    if 'detected_urls' in results:
        for u in map(urllib.parse.urlparse, [x['url'] for x in results['detected_urls']]):
            my_uri = add_uri(actapi, 'fqdn', u.netloc, list(u))
            act.api.helpers.handle_fact(actapi.fact('at')
                                        .source('content', content_id)
                                        .destination('uri', my_uri),
                                        output_format=output_format)
    if 'undetected_urls' in results:
        for u in map(urllib.parse.urlparse, [x[0] for x in results['undetected_urls']]):
            my_uri = add_uri(actapi, 'fqdn', u.netloc, list(u))
            act.api.helpers.handle_fact(actapi.fact('at')
                                        .source('content', content_id)
                                        .destination('uri', my_uri),
                                        output_format=output_format)


def handle_ip(actapi: act.api.Act, vtapi: VirusTotalApi, ip: Text, output_format: Text = "json") -> None:
    """Read IP address from stdin, query VirusTotal and
    output a JSON text readable by generic_uploaderr.py"""

    # To figure out what kind of IP address we have, let the ipaddress module
    # parse the string and test for instance type as the platform distinguishes
    # between IPv4 and IPv6 addresses.
    try:
        (ip_type, ip) = act.api.helpers.ip_obj(ip)
    except ValueError:
        return  # invalid address

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
            act.api.helpers.handle_fact(actapi.fact('resolvesTo')
                                        .source('fqdn', resolution['hostname'])
                                        .destination(ip_type, ip),
                                        output_format=output_format)
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

            act.api.helpers.handle_fact(actapi.fact('at')
                                        .source('content', sample['sha256'])
                                        .destination('uri', my_uri),
                                        output_format=output_format)

            act.api.helpers.handle_fact(actapi.fact('represents')
                                        .source('hash', sample['sha256'])
                                        .destination('content', sample['sha256']),
                                        output_format=output_format)

            handle_hexdigest(actapi, vtapi, sample['sha256'], output_format=output_format)

    if 'detected_communicating_samples' in results:
        for sample in results['detected_communicating_samples']:
            my_uri = add_uri(actapi, ip_type, ip, ['network', ip, '', '', '', ''])

            act.api.helpers.handle_fact(actapi.fact('connectsTo')
                                        .source('content', sample['sha256'])
                                        .destination('uri', my_uri),
                                        output_format=output_format)

            act.api.helpers.handle_fact(actapi.fact('represents')
                                        .source('hash', sample['sha256'])
                                        .destination('content', sample['sha256']),
                                        output_format=output_format)

            handle_hexdigest(actapi, vtapi, sample['sha256'], output_format=output_format)


def add_uri(actapi: act.api.Act,
            addr_type: str,
            addr: str,
            url: List[str],
            cache: dict = {},
            output_format: Text = "json") -> str:
    """Add a URI to the platform by creating the componentOf and scheme facts
If called multiple times with arguments creating the same URI, the facts will only sent once.
Return: The URI added
"""
    try:
        my_uri = str(urllib.parse.urlunparse(url))
        if my_uri in cache:
            return my_uri

        cache[my_uri] = True

        act.api.helpers.handle_fact(actapi.fact("componentOf")
                                    .source(addr_type, addr)
                                    .destination("uri", my_uri),
                                    output_format=output_format)

        act.api.helpers.handle_fact(actapi.fact("scheme", url[0])
                                    .source("uri", my_uri),
                                    output_format=output_format)

        if url[2] and not url[2].strip() == "/":  # path
            act.api.helpers.handle_fact(actapi.fact("componentOf")
                                        .source("path", url[2])
                                        .destination("uri", my_uri),
                                        output_format=output_format)

            basename = os.path.basename(url[2])
            if basename.strip():
                act.api.helpers.handle_fact(actapi.fact("basename", basename)
                                            .source("path", url[2]),
                                            output_format=output_format)

        if url[3]:  # query
            act.api.helpers.handle_fact(actapi.fact("componentOf")
                                        .source("query", url[3])
                                        .destination("uri", my_uri),
                                        output_format=output_format)

    except act.api.base.ResponseError as e:
        error(str(e))

    return my_uri


def handle_domain(
        actapi: act.api.Act,
        vtapi: VirusTotalApi,
        domain: Text,
        output_format: Text = "json") -> None:
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
                act.api.helpers.handle_fact(actapi.fact('resolvesTo')
                                            .source('fqdn', domain)
                                            .destination(*act.api.helpers.ip_obj(ip)),
                                            output_format=output_format)
            except ValueError:
                continue  # invalid address

    if 'detected_downloaded_samples' in results:
        for sample in results['detected_downloaded_samples']:
            my_uri = add_uri(actapi, 'fqdn', domain, ['network', domain, '', '', '', ''])
            act.api.helpers.handle_fact(actapi.fact('at')
                                        .source('content', sample['sha256'])
                                        .destination('uri', my_uri),
                                        output_format=output_format)
            act.api.helpers.handle_fact(actapi.fact('represents')
                                        .source('hash', sample['sha256'])
                                        .destination('content', sample['sha256']),
                                        output_format=output_format)
            handle_hexdigest(actapi, vtapi, sample['sha256'], output_format=output_format)

    if 'detected_communicating_samples' in results:
        for sample in results['detected_communicating_samples']:
            my_uri = add_uri(actapi, 'fqdn', domain, ['network', domain, '', '', '', ''])
            act.api.helpers.handle_fact(actapi.fact('connectsTo')
                                        .source('content', sample['sha256'])
                                        .destination('uri', my_uri),
                                        output_format=output_format)
            act.api.helpers.handle_fact(actapi.fact('represents')
                                        .source('hash', sample['sha256'])
                                        .destination('content', sample['sha256']),
                                        output_format=output_format)
            handle_hexdigest(actapi, vtapi, sample['sha256'], output_format=output_format)


def handle_ioc(actapi: act.api.Act,
        vtapi: VirusTotalApi,
        ioc: Text,
        output_format: Text = "json") -> None:
    "Autodetect IOC type and send to correct handler"

    # Attempt to parse ioc AS IP address
    try:
        ipaddress.ip_address(ioc)
        info("Autodetected IOC as IP address: {}".format(ioc))
        handle_ip(actapi, vtapi, ioc, output_format=output_format)
        return
    except ValueError:  # Not IP, continue to next
        pass

    # md5, sha1 or sha256 or sha512 hash?
    if HASH_RE.search(ioc):
        info("Autodetected IOC as hash: {}".format(ioc))
        handle_hexdigest(actapi, vtapi, ioc, output_format=output_format)
        return

    # Assume domain
    info("Autodetection assumes IOC is domain: {}".format(ioc))
    handle_domain(actapi, vtapi, ioc, output_format=output_format)


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not args.apikey:
        worker.fatal("You must specify --apikey on command line or in config file")

    in_data = sys.stdin.read().strip()

    proxies = {
        'http': args.proxy_string,
        'https': args.proxy_string
    } if args.proxy_string else None

    vtapi = VirusTotalApi(args.apikey, proxies=proxies)

    if args.hexdigest:
        handle_hexdigest(actapi, vtapi, in_data, output_format=args.output_format)

    elif args.ip:
        handle_ip(actapi, vtapi, in_data, output_format=args.output_format)

    elif args.domain:
        handle_domain(actapi, vtapi, in_data, output_format=args.output_format)

    else:  # Type not specified, autodetect
        handle_ioc(actapi, vtapi, in_data, output_format=args.output_format)



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
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
