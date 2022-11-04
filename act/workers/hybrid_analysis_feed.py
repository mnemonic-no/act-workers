#!/usr/bin/env python3

"""hybrid-analysis.com worker for the ACT platform

Copyright 2021 the ACT project <opensource@mnemonic.no>

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

import argparse
import contextlib
import json
import sys
import traceback
import warnings
from functools import partialmethod
from logging import error, info, warning
from typing import Any, Dict, Generator, List, Optional, Text

import act.api
import requests
from act.api.libs import cli

from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs("ACT hybrid-analysis.com Client")

    parser.add_argument(
        "--feed", action="store_true", help="Download the public feed only, no lookup"
    )

    parser.add_argument(
        "--apikey", default="", help="community apikey for hybrid-analysis.com"
    )

    parser.add_argument(
        "--user-agent", default="Falcon Sandbox", help="User agent while talking to API"
    )

    parser.add_argument(
        "--no-check-certificate",
        action="store_true",
        help="Do not check SSL certificate",
    )

    return parser


def download_feed(
    user_agent: Text, proxies: Optional[Dict[Text, Text]], verify_ssl: bool = True
) -> Dict[Text, Any]:
    """Download the public feed and return a dictionary"""

    url = "https://hybrid-analysis.com/feed?json"

    with ssl_verification(verify=verify_ssl):
        headers = {"User-Agent": user_agent}
        response = requests.get(url, proxies=proxies, headers=headers)

    if response.status_code == 525:
        # This is a known error that is observed from from time to time towards the hybrid analsysi API
        warning(
            f"hybrid_analysis_feed.download_feed() could not download public feed, "
            f"error calling {url}: Status = {response.status_code}"
        )

        return {"data": []}

    elif response.status_code != 200:
        raise CommunicationError(
            f"hybrid_analysis_feed.download_feed() could not download public feed, "
            f"error calling {url}: Status = {response.status_code}"
        )

    try:
        data: Dict[Text, Any] = response.json()
    except json.decoder.JSONDecodeError as err:
        raise CommunicationError(
            f"hybrid_analysis_feed.download_feed() could not load public feed, "
            f"error decoding json result from {url}: {err}"
        )

    return data


def handle_feed(
    actapi: act.api.Act,
    user_agent: Text,
    proxies: Optional[Dict[Text, Text]] = None,
    verify_ssl: bool = True,
    output_format: Text = "json",
) -> None:
    """Download, parse and provide facts from the public feed of hybrid-analysis.com"""

    feed = download_feed(user_agent, proxies, verify_ssl)

    feeds_facts: List[act.api.fact.Fact] = []

    for report in feed["data"]:
        if not (report.get("isinteresting", False) or report.get("threatlevel", 0)):
            continue
        # store data if threatlevel > 0 or report is interesting

        if "sha256" not in report:
            continue

        feeds_facts += handle_report(actapi, report)

    for fact in feeds_facts:
        act.api.helpers.handle_fact(fact, output_format=output_format)


def handle_hosts(
    actapi: act.api.Act, content: Text, hosts: List[Text]
) -> List[act.api.fact.Fact]:
    """handle the hosts part of a hybrid-analysis report"""

    feeds_facts: List[act.api.fact.Fact] = []

    for host in hosts:
        (ip_type, ip) = act.api.helpers.ip_obj(host)

        chain = []

        chain.append(
            actapi.fact("connectsTo").source("content", content).destination("uri", "*")
        )
        chain.append(
            actapi.fact("resolvesTo").source("fqdn", "*").destination(ip_type, ip)
        )
        chain.append(
            actapi.fact("componentOf").source("fqdn", "*").destination("uri", "*")
        )

        feeds_facts += act.api.fact.fact_chain(*chain)

    return feeds_facts


def handle_domains(
    actapi: act.api.Act, content: Text, domains: List[Text]
) -> List[act.api.fact.Fact]:
    """Handle the domains part of a hybrid-analysis report"""

    feeds_facts: List[act.api.fact.Fact] = []

    for domain in domains:

        chain = []

        chain.append(
            actapi.fact("connectsTo").source("content", content).destination("uri", "*")
        )
        chain.append(
            actapi.fact("componentOf").source("fqdn", domain).destination("uri", "*")
        )

        feeds_facts += act.api.fact.fact_chain(*chain)

    return feeds_facts


def handle_extracted_files(
    actapi: act.api.Act, content: Text, extracted_files: List[Dict]
) -> List[act.api.fact.Fact]:
    """Handle the extracted_files part of a hybrid_analysis report"""

    feeds_facts: List[act.api.fact.Fact] = []

    for file in extracted_files:

        chain = []

        if "sha256" not in file:
            continue

        if not file["file_path"]:
            info(f"{file} is missing file_path using name instead")

        path = file["file_path"] if file["file_path"] else file["name"]

        chain.append(
            actapi.fact("componentOf").source("path", path).destination("uri", "*")
        )

        chain.append(
            actapi.fact("at").source("content", file["sha256"]).destination("uri", "*")
        )

        feeds_facts += act.api.fact.fact_chain(*chain)

        for hash_type in ["md5", "sha1", "sha256"]:
            feeds_facts.append(
                actapi.fact("represents")
                .source("hash", file[hash_type])
                .destination("content", file["sha256"])
            )
            feeds_facts.append(
                actapi.fact("category", hash_type).source("hash", file[hash_type])
            )

        if (
            content != file["sha256"]
        ):  # the act platform does not accept same object on source and destination for write
            feeds_facts.append(
                actapi.fact("writes")
                .source("content", content)
                .destination("content", file["sha256"])
            )

    return feeds_facts


def handle_classification_tags(
    actapi: act.api.Act, content: Text, classification_tags: List[Text]
) -> List[act.api.fact.Fact]:
    """handle the classification_tags part or a hybrid_analysis report"""

    feeds_facts: List[act.api.fact.Fact] = []

    for tag in classification_tags:
        feeds_facts.append(
            actapi.fact("classifiedAs")
            .source("content", content)
            .destination("tool", tag)
        )

    return feeds_facts


def handle_mitre_attcks(
    actapi: act.api.Act, content: Text, mitre_attcks: List[Dict]
) -> List[act.api.fact.Fact]:
    """Handle the MITRE Att&ck part of the hybrid analysis report"""

    feeds_facts: List[act.api.fact.Fact] = []

    for attck in mitre_attcks:
        chain = []

        chain.append(
            actapi.fact("classifiedAs")
            .source("content", content)
            .destination("tool", "*")
        )
        chain.append(
            actapi.fact("implements")
            .source("tool", "*")
            .destination("technique", attck["technique"])
        )

        feeds_facts += act.api.fact.fact_chain(*chain)

    return feeds_facts


def handle_process_list(
    actapi: act.api.Act, content: Text, process_list: List[Dict]
) -> List[act.api.fact.Fact]:
    """Handle the process list part of the hybrid analysis report"""

    feeds_facts: List[act.api.fact.Fact] = []

    for proc in process_list:

        chain = []

        path = proc["normalizedpath"] if "normalizedpath" in proc else proc["name"]

        if not path.strip():
            continue

        chain.append(
            actapi.fact("executes").source("content", content).destination("uri", "*")
        )
        chain.append(
            actapi.fact("componentOf").source("path", path).destination("uri", "*")
        )

        feeds_facts += act.api.fact.fact_chain(*chain)

    return feeds_facts


def handle_report(
    actapi: act.api.Act, report: Dict[Text, Any]
) -> List[act.api.fact.Fact]:
    """Create facts from a report"""

    feeds_facts: List[act.api.fact.Fact] = []

    content = report["sha256"]
    for hash_type in ["md5", "sha1", "sha256", "ssdeep", "imphash", "sha512"]:
        if (
            hash_type not in report
            or not report[hash_type]
            or report[hash_type] == "Unknown"
        ):
            info(f"{hash_type} not set for content {content}")
            continue
        feeds_facts.append(
            actapi.fact("represents")
            .source("hash", report[hash_type])
            .destination("content", content)
        )
        feeds_facts.append(
            actapi.fact("category", hash_type).source("hash", report[hash_type])
        )

    feeds_facts += handle_hosts(actapi, content, report.get("hosts", []))
    feeds_facts += handle_domains(actapi, content, report.get("domains", []))
    feeds_facts += handle_extracted_files(
        actapi, content, report.get("extracted_files", [])
    )
    feeds_facts += handle_classification_tags(
        actapi, content, report.get("classification_tags", [])
    )

    # DISABLED DUE TO EXCESSIVE FACT CHAIN OBJECT. TO BE DISCUSSED
    # feeds_facts += handle_mitre_attcks(actapi, content, report.get("mitre_attcks", []))

    feeds_facts += handle_process_list(actapi, content, report.get("process_list", []))

    return feeds_facts


def handle_hash(
    actapi: act.api.Act,
    apikey: Text,
    hashdigest: Text,
    user_agent: Text,
    proxies: Optional[Dict[Text, Text]] = None,
    verify_ssl: bool = True,
    output_format: Text = "json",
) -> None:
    """Download, parse and provide facts from the public feed of hybrid-analysis.com"""

    data = search_hash(apikey, hashdigest, user_agent, proxies, verify_ssl)

    for report in data:
        for fact in handle_report(actapi, report):
            act.api.helpers.handle_fact(fact, output_format=output_format)


def search_hash(
    apikey: Text,
    hashdigest: Text,
    user_agent: Text,
    proxies: Optional[Dict[Text, Text]] = None,
    verify_ssl: bool = True,
) -> List[Dict[Text, Any]]:
    """Search the hybrid-analysis api for a specific hash"""

    url = "https://www.hybrid-analysis.com/api/v2/search/hash"

    with ssl_verification(verify=verify_ssl):
        headers = {
            "User-Agent": user_agent,
            "accept": "application/json",
            "api-key": apikey,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        form_data = {"hash": hashdigest}

        response = requests.post(url, proxies=proxies, headers=headers, data=form_data)

    if response.status_code == 525:
        # This is a known error that is observed from from time to time towards the hybrid analsysi API
        warning(
            f"hybrid_analysis_feed.search_hash() could not search community API, "
            f"error calling {url}: Status = {response.status_code}, response = {response.text}"
        )

        return []

    if response.status_code != 200:
        raise CommunicationError(
            f"hybrid_analysis_feed.search_hash() could not search community API, "
            f"error calling {url}: Status = {response.status_code}, response = {response.text}"
        )

    try:
        data: List[Dict[Text, Any]] = response.json()
    except json.decoder.JSONDecodeError as err:
        raise CommunicationError(
            f"hybrid_analysis_feed.search_hash() could not load search result, "
            f"error decoding json result from {url}: {err}"
        )

    return data


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    actapi = worker.init_act(args)

    # if not args.apikey:
    #    cli.fatal("You must specify --apikey on command line or in config file")

    proxies = (
        {"http": args.proxy_string, "https": args.proxy_string}
        if args.proxy_string
        else None
    )

    params = {
        "actapi": actapi,
        "user_agent": args.user_agent,
        "proxies": proxies,
        "verify_ssl": args.no_check_certificate,
        "output_format": args.output_format,
    }

    if args.feed:
        handle_feed(**params)
    else:
        params["apikey"] = args.apikey
        for line in sys.stdin:
            params["hashdigest"] = line.strip()
            handle_hash(**params)


@contextlib.contextmanager
def ssl_verification(verify: bool = True) -> Generator[None, None, None]:
    """Monkey patch request to manage ssl verification. Can be used 'around' code
    that uses requests internally"""

    old_request = requests.Session.request
    requests.Session.request = partialmethod(old_request, verify=verify)  # type: ignore

    warnings.filterwarnings("ignore", "Unverified HTTPS request")
    yield
    warnings.resetwarnings()

    requests.Session.request = old_request  # type: ignore


class CommunicationError(Exception):
    """CommunicationError is used to gather all communication errors into one"""

    ...


def main_log_error() -> None:
    """Main entry point, catching and logging errors"""

    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
