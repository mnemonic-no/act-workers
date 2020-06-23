#!/usr/bin/env python3

'''iSight worker for the ACT platform

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

'''


from functools import partialmethod
from logging import error
from typing import Generator, Text, Dict

import argparse
import contextlib
import datetime
import email
import hashlib
import hmac
import json
import logging
import os
import requests
import socket
import time
import traceback
import warnings

import act.api
from act.api.helpers import handle_fact, handle_uri
from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs('ACT iSight Client')
    parser.add_argument('--privatekey', metavar='PRIVATEKEY',
                        help='iSight API key')
    parser.add_argument('--publickey', metavar='PUBLICKEY',
                        help='iSight API key')
    parser.add_argument('--debugdir', metavar='DIR',
                        help='Dump directory for output')
    parser.add_argument(
        '--days',
        default='1',
        help='How many days back to look for data')
    parser.add_argument(
        '--root',
        default='https://api.isightpartners.com',
        help='api endpoint')

    return parser


def is_valid_ipv4_address(address: Text) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, address)
    except socket.error:  # not a valid address
        return False
    return True


def is_valid_ipv6_address(address: Text) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


OBJECT_MAP = {
    "sourceDomain": lambda x: "fqdn",
    "sourceIP": lambda x: "ipv4" if is_valid_ipv4_address(x) else "ipv6" if is_valid_ipv6_address(x) else None,
    "fuzzyHash": lambda x: "hash",
    "md5": lambda x: "hash",
    "sha1": lambda x: "hash",
    "sha256": lambda x: "hash",
    "asn": lambda x: "asn",
    "cidr": lambda x: "ipv4Network",
    "domain": lambda x: "fqdn",
    "ip": lambda x: "ipv4" if is_valid_ipv4_address(x) else "ipv6" if is_valid_ipv6_address(x) else None,
    "malwareFamily": lambda x: "tool",
    "actor": lambda x: "threatActor",
}


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not (args.privatekey and args.publickey):
        worker.fatal("You must specify --privatekey and --publickey on command line or in config file")

    proxies = {
        'http': args.proxy_string,
        'https': args.proxy_string
    } if args.proxy_string else None

    iSightHandler = ISightAPIRequestHandler(args.root, args.privatekey, args.publickey)
    data = iSightHandler.indicators(days=args.days, proxies=proxies)

    if 'success' not in data or not data['success']:
        logging.error("Unable to download from isight API [%s]", data['message'] if 'message' in data else "NA")
        return

    timestamp = int(time.time())
    ### DEBUG -- dump json to disc for each run
    if args.debugdir:
        with open(os.path.join(args.debugdir, "error-{0}.json".format(timestamp)), "w") as f:
            json.dump(data, f)

    for i, dp in enumerate(data['message']):
        ### --- Handle mentions facts
        # Create report ID from the url (same approach as for feeds) and title to this ID.
        reportID = hashlib.sha256(dp['webLink'].encode('utf8')).hexdigest()
        handle_fact(actapi.fact('name', dp['title']).source('report', reportID))
        for obj in OBJECT_MAP:  # run through all fields that we want to mention
            if obj in dp and dp[obj]:  # if the report contains data in the field
                factType = OBJECT_MAP[obj](dp[obj])  # translate to ACT fact type
                handle_fact(actapi.fact('mentions')  # and create fact from field
                            .source('report', reportID)
                            .destination(factType, dp[obj].lower()))
        if dp['url']:
            handle_fact(actapi.fact('mentions')
                        .source('report', reportID)
                        .destination('uri', dp['url']))
            try:
                handle_uri(actapi, dp['url'])
            except act.api.base.ValidationError as err:
                logging.error("%s while storing url from mentions [%s]", err, dp['url'])
        ### --- IP -> malwareFamily
        if dp['malwareFamily'] and dp['ip']:
            chain = act.api.fact.fact_chain(
                actapi.fact('connectsTo')
                .source('content', '*')
                .destination('uri', '*'),
                actapi.fact('componentOf')
                .source('ipv4', dp['ip'])
                .destination('uri', '*'),
                actapi.fact('classifiedAs')
                .source('content', '*')
                .destination('tool', dp['malwareFamily'].lower()))
            for fact in chain:
                handle_fact(fact)
        ### --- URL -> malwareFamily
        elif dp['networkType'] == 'url' and dp['malwareFamily']:
            try:
                handle_uri(actapi, dp['url'])
            except act.api.base.ValidationError as err:
                logging.error("%s while storing url from mentions [%s]", err, dp['url'])

            chain = act.api.fact.fact_chain(
                actapi.fact('connectsTo')
                .source('content', '*')
                .destination('uri', dp['url']),
                actapi.fact('classifiedAs')
                .source('content', '*')
                .destination('tool', dp['malwareFamily'].lower()))
            for fact in chain:
                handle_fact(fact)
        ### --- FQDN -> malwareFamily
        elif dp['networkType'] == 'network' and dp['domain'] and dp['malwareFamily']:
            chain = act.api.fact.fact_chain(
                actapi.fact('connectsTo')
                .source('content', '*')
                .destination('uri', '*'),
                actapi.fact('componentOf')
                .source('fqdn', dp['domain'])
                .destination('uri', '*'),
                actapi.fact('classifiedAs')
                .source('content', '*')
                .destination('tool', dp['malwareFamily'].lower()))
            for fact in chain:
                handle_fact(fact)
        ### --- hash -> malwareFamily
        elif dp['fileType'] and dp['malwareFamily'] and (dp['sha1'] or dp['sha256'] or dp['md5']):
            for digest_type in ['md5', 'sha1', 'sha256']:
                ### In some cases the iSight api does not return a sha256 hashdigest
                ### so we need to make a chain through a placeholder content
                if not dp['sha256']:
                    if dp[digest_type]:
                        chain = act.api.fact.fact_chain(
                            actapi.fact('represents')
                            .source('hash', dp[digest_type])
                            .destination('content', '*'),
                            actapi.fact('classifiedAs')
                            .source('content', '*')
                            .destination('tool', dp['malwareFamily']))
                        for fact in chain:
                            handle_fact(fact)
                else:  ## There is a sha256, so we do _not_ need a chain
                    if dp[digest_type]:
                        handle_fact(actapi.fact('classifiedAs')
                                    .source('content', dp['sha256'])
                                    .destination('tool', dp['malwareFamily']))
                        handle_fact(actapi.fact('represents')
                                    .source('hash', dp[digest_type])
                                    .destination('content', dp['sha256']))
        ### -- Hash --> actor
        elif dp['fileType'] and dp['actor'] and (dp['sha1'] or dp['sha256'] or dp['md5']):
            for digest_type in ['md5', 'sha1', 'sha256']:
                ### In some cases the iSight api does not return a sha256 hashdigest
                ### so we need to make a chain through a placeholder content
                if not dp['sha256']:
                    if dp[digest_type]:
                        chain = act.api.fact.fact_chain(
                            actapi.fact('represents')
                            .source('hash', dp[digest_type])
                            .destination('content', '*'),
                            actapi.fact('observedIn')
                            .source('content', '*')
                            .destination('event', '*'),
                            actapi.fact('attributedTo')
                            .source('event', '*')
                            .destination('incident', '*'),
                            actapi.fact('attributedTo')
                            .source('incident', '*')
                            .destination('threatActor', dp['actor']))
                        for fact in chain:
                            handle_fact(fact)
                else:  ## There is a sha256, so we do _not_ need a chain between all the way from hexdigest
                    if dp[digest_type]:
                        handle_fact(actapi.fact('represents')
                                    .source('hash', dp[digest_type])
                                    .destination('content', dp['sha256']))
                        chain = act.api.fact.fact_chain(
                            actapi.fact('observedIn')
                            .source('content', dp['sha256'])
                            .destination('event', '*'),
                            actapi.fact('attributedTo')
                            .source('event', '*')
                            .destination('incident', '*'),
                            actapi.fact('attributedTo')
                            .source('incident', '*')
                            .destination('threatActor', dp['actor']))
                        for fact in chain:
                            handle_fact(fact)
        ### We do have a sha256 of a file (but possibly nothing else). Add the content to hexdigest facts
        elif dp['fileType'] and dp['sha256']:
            for digest in ['sha1', 'md5', 'sha256']:
                if dp[digest]:
                    print("DEBUG!!!")
                    handle_fact(actapi.fact('represents')
                                .source('hash', dp[digest])
                                .destination('content', dp['sha256']))
            if args.debugdir:
                fields = [k for k, v in dp.items() if v and k not in ['reportId', 'title', 'ThreatScape',
                                                                      'audience', 'intelligenceType',
                                                                      'publishDate', 'reportLink', 'webLink']]
                logging.error("[%s] Extra fields while handeling index[%s] '%s'", timestamp, i, ", ".join(fields))


        ### -- DEBUG!
        else:
            if args.debugdir:
                fields = [k for k, v in dp.items() if v and k not in ['reportId', 'title', 'ThreatScape',
                                                                      'audience', 'intelligenceType',
                                                                      'publishDate', 'reportLink', 'webLink']]
                logging.error("[%s] Unable to handle index[%s] with fields '%s'", timestamp, i, ", ".join(fields))

## -----------------------------------------


class ISightAPIRequestHandler(object):

    INDICATORS = '/view/indicators'

    def __init__(self, root: Text, private_key: Text, public_key: Text) -> None:
        """Create a new iSight api handler with api root and keys"""

        self.URL = root
        self.public_key = public_key
        self.private_key = private_key
        self.accept_version = '2.6'

    def indicators(self, days: int = 1, proxies: Dict = None) -> Dict:
        """Download indicators last X days"""

        toTS = int(datetime.datetime.now().timestamp())
        fromTS = int((datetime.datetime.now() - datetime.timedelta(days=int(days))).timestamp())

        time_stamp = email.utils.formatdate(localtime=True)
        ENDPOINT = self.INDICATORS + "?startDate={0}&endDate={1}".format(fromTS, toTS)
        accept_header = 'application/json'
        new_data = ENDPOINT + self.accept_version + accept_header + time_stamp

        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }

        r = requests.get(self.URL + ENDPOINT, headers=headers, proxies=proxies)
        status_code = r.status_code

        if status_code == 200:
            return json.loads(r.text)
        else:
            logging.error(r.text)
            return {'message': r.text}


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
