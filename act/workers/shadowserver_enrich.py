import argparse
import hashlib
import hmac
import json
import logging
import re
import sys
import traceback
from typing import Dict, Text
from urllib.parse import urljoin

import act.api
import requests
from act.api.libs import cli
from urllib3.exceptions import MaxRetryError

from act.workers.libs import worker

BASEURL = "https://transform.shadowserver.org/api2/"

# Type:Platform/Family.Variant!Suffixes
MS_RE = re.compile(r"(.*?):(.*?)\/(?:([^!.]+))?(?:[!.](\w+))?")
HASH_RE = re.compile(r"^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$")


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs("ACT Shadowserver Client")
    parser.add_argument("--apikey", metavar="KEY", help="Shadowserver API key")
    parser.add_argument("--secret", help="Shadowserver secret")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--hexdigest",
        action="store_true",
        default=False,
        help="Skip autodetection of type and force lookup as hexdigest",
    )
    group.add_argument(
        "--domain",
        action="store_true",
        default=False,
        help="Skip autodetection of type and force lookup as domain",
    )

    return parser


def query_shadowserver(
    endpoint: Text,
    request: Dict,
    secret: Text,
    proxies: Dict = None,
) -> Dict:

    url = urljoin(BASEURL, endpoint)
    request_string = json.dumps(request)
    secret_bytes = bytes(secret, "latin-1")
    request_bytes = bytes(request_string, "latin-1")
    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    hmac2 = hmac_generator.hexdigest()

    try:
        response = requests.post(
            url=url, json=request, proxies=proxies, headers={"HMAC2": hmac2}
        )
    except MaxRetryError as err:
        return dict(error=err)

    if response.status_code == requests.codes.ok:
        return dict(
            results=response.json(),
            response_code=response.status_code,
        )
    else:
        return dict(
            error=response.text,
            response_code=response.status_code,
            proxies=proxies,
        )


def name_extraction(
    actapi: act.api.Act, signature: Text, content_id: Text, output_format: Text = "json"
) -> None:
    """Submit if AV vendor is Microsoft"""
    match = MS_RE.match(signature)

    if match:
        name, toolType = match.groups()[2].lower(), match.groups()[0].lower()
        act.api.helpers.handle_fact(
            actapi.fact("classifiedAs")
            .source("content", content_id)
            .destination("tool", name),
            output_format=output_format,
        )

        if toolType:
            act.api.helpers.handle_fact(
                actapi.fact("classifiedAs")
                .source("tool", name)
                .destination("toolType", toolType),
                output_format=output_format,
            )


def handle_hexdigest(
    actapi: act.api.Act, ioc, apikey, secret, proxies, output_format: Text = "json"
) -> None:
    request = {"apikey": apikey}
    request["sample"] = ioc
    response = query_shadowserver(
        endpoint="research/malware-info",
        request=request,
        secret=secret,
        proxies=proxies,
    )
    try:
        results = response["results"]
    except KeyError:
        logging.warning(f"Error handling: {ioc}. Error: {response['error']}")
        sys.exit(1)

    for result in results:
        content_id = result["sha256"]
        for my_hash in ["sha1", "sha256", "sha512", "md5"]:
            act.api.helpers.handle_fact(
                actapi.fact("represents")
                .source("hash", result[my_hash])
                .destination("content", content_id),
                output_format=output_format,
            )

        for r in result["anti_virus"]:
            if r["vendor"] == "Microsoft":
                name_extraction(
                    actapi=actapi, signature=r["signature"], content_id=content_id
                )

        if "domain_name" in result:
            for body in result["domain_name"]:
                if "tag" in body:
                    if "tno-dga-tagged" in body["tag"]:
                        act.api.helpers.handle_facts(
                            act.api.fact.fact_chain(
                                actapi.fact("connectsTo")
                                .source("content", content_id)
                                .destination("uri", "*"),
                                actapi.fact("componentOf")
                                .source("fqdn", body["domain"])
                                .destination("uri", "*"),
                            )
                        )


def handle_domain(
    actapi: act.api.Act, ioc, apikey, secret, proxies, output_format: Text = "json"
) -> None:

    request = {"apikey": apikey}
    request["domain"] = ioc
    response = query_shadowserver(
        endpoint="research/malware-domain",
        request=request,
        secret=secret,
        proxies=proxies,
    )

    try:
        results = response["results"][ioc]
    except KeyError:
        logging.warning(f"Error handling: {ioc}. Error: {response['error']}")
        sys.exit(1)

    if not "family" in results:
        logging.warning(f"No family in results: {results}")
        return

    if isinstance(results["family"], str):
        results["family"] = [results["family"]]

    for tool_name in results["family"]:
        for sample in results["samples"]:

            content_id = sample["sha256"]

            act.api.helpers.handle_fact(
                actapi.fact("classifiedAs")
                .source("content", content_id)
                .destination("tool", tool_name),
                output_format=output_format,
            )

            for my_hash in ["sha1", "sha256", "md5"]:
                act.api.helpers.handle_fact(
                    actapi.fact("represents")
                    .source("hash", sample[my_hash])
                    .destination("content", content_id),
                    output_format=output_format,
                )

            for result in sample["anti_virus"]:
                if result["vendor"] == "Microsoft":
                    name_extraction(actapi, result["signature"], content_id)


def run() -> None:
    args = cli.handle_args(parseargs())
    actapi = worker.init_act(args)

    if not args.apikey or not args.secret:
        cli.fatal(
            "You must specify --apikey and --secret on command line or in config file"
        )

    proxies = (
        {"http": args.proxy_string, "https": args.proxy_string}
        if args.proxy_string
        else None
    )

    for in_data in sys.stdin:
        in_data = in_data.strip()

        if args.hexdigest or HASH_RE.search(in_data):
            handle_hexdigest(
                actapi,
                in_data,
                args.apikey,
                args.secret,
                proxies,
                output_format=args.output_format,
            )

        elif args.domain:
            handle_domain(
                actapi,
                in_data,
                args.apikey,
                args.secret,
                proxies,
                output_format=args.output_format,
            )


def main_log_error() -> None:
    try:
        run()
    except Exception:
        logging.error(f"Unhandled exception: {traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main_log_error()
