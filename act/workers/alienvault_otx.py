#!/usr/bin/env python3
"""Alienvault OTX Worker for the ACT Project

Copyright 2018,2021 the ACT project <opensource@mnemonic.no>

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
import datetime
import hashlib
import logging
import os
import traceback
import urllib.parse
from typing import Any, Dict, Generator, Optional, Text

import act.api
import pid
import requests
from act.api.libs import cli

import act
from act.workers.libs import worker

WORKER_NAME = "alienvault-otx"
VERSION = 0.1

OTX_ACT_TYPE_MAPPING: Dict[Text, Text] = {
    "CVE": "vulnerability",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
    "FilePath": "uri",
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "Mutex": "mutex",
    "URI": "path",
    "URL": "uri",
    "domain": "fqdn",
    "email": "uri",
    "hostname": "fqdn",
}


class AuthorizationError(Exception):
    """AutorizationError raised if API returns status code 403"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class AlienvaultOTXAPI:
    """Class for interacting with Alienvault OTX API"""

    def __init__(self, args: argparse.Namespace) -> None:
        """Initialisation method"""
        self.args = args

    def __api_request(self, api_url: Text) -> Any:
        """Method for sending API requests to the Alienvault OTX API"""

        # add necessary headers
        headers: Dict[Text, Text] = {
            "Content-Type": "application/json",
            "X-OTX-API-KEY": self.args.otx_apikey,
        }

        # check if we should use a proxy
        proxy: Dict[Text, Text] = {}
        if "proxy_string" in self.args:
            proxy = {
                "http": self.args.proxy_string,
                "https": self.args.proxy_string,
            }

        # make api request
        request = requests.get(
            api_url,
            headers=headers,
            proxies=proxy,
        )

        # check for 403 status code
        if request.status_code == 403:
            raise AuthorizationError("Authentication required")

        # will raise exception if no json is returned which is how the api behaves
        # if you specify a wrong url
        return request.json()

    def get_subscribed(self) -> Generator[Dict[Any, Any], None, None]:
        """Method for getting events from pulses you are subscribed to"""

        # get last updated timestamp
        last_updated = self.last_retrived()

        # generate full api url
        if last_updated:
            api_url = urllib.parse.urljoin(
                self.args.otx_baseurl,
                f"v1/pulses/subscribed?modified_since={last_updated}",
            )
        else:
            api_url = urllib.parse.urljoin(
                self.args.otx_baseurl, "v1/pulses/subscribed"
            )

        # do api request
        data = self.__api_request(api_url)

        # iterate through pages with results
        while True:
            for entry in data["results"]:
                yield entry

            if "next" in data and data["next"]:
                data = self.__api_request(data["next"])
            else:
                break

        # update last retrived timestamp
        self.last_retrived(update=True)

    def last_retrived(self, update: bool = False) -> Optional[Text]:
        """Method for handling last retrived timestamp"""

        # if update is set, just write current timestamp to filepath
        if update:
            with open(self.args.otx_path_lastretrived, "w") as file_handle:
                timestamp = datetime.datetime.utcnow().isoformat()
                file_handle.write(timestamp)

        # update is not set, try to return previous timestamp
        else:
            # file does not exist, return None
            if not os.path.isfile(self.args.otx_path_lastretrived):
                return None

            # try to read file, parse timestamp, and return it
            with open(self.args.otx_path_lastretrived, "r") as file_handle:
                try:
                    timestamp = str(
                        datetime.datetime.strptime(
                            file_handle.read(), "%Y-%m-%dT%H:%M:%S.%f"
                        )
                    )
                    return timestamp
                except ValueError:
                    return None

        # fallback
        return None


class ConfigurationError(Exception):
    """Raised when invalid option for events to import is used"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs("ACT Alienvault OTX Import Client v{}".format(VERSION))
    parser.add_argument(
        "--config_path", metavar="PATH", help="Path to reputation configuration files"
    )
    parser.add_argument(
        "--otx-baseurl",
        default="https://otx.alienvault.com/api/",
        help="Alienvault OTX API host",
    )
    parser.add_argument("--otx-apikey", metavar="KEY", help="Alienvault OTX API key")
    parser.add_argument(
        "--otx-path-lastretrived",
        metavar="FILEPATH",
        help="Path to store last retrival timestamp",
    )
    return parser


def strip_special_chars(msg: Text) -> Text:
    """Strips special chars from a string"""
    for char in ["\r\n", "\n", "\r"]:
        msg = msg.replace(char, " ")

    return msg


def handle_facts(actapi: act.api.helpers.Act, event: Dict[Any, Any]) -> None:
    """Generates a list of json facts based on a given ioc"""

    # generate report name - sha256
    report_id: Text = hashlib.sha256(
        f'alienvault-otx-{event["id"]}-{event["modified"]}'.encode("utf-8")
    ).hexdigest()

    # add a name fact to the report
    if "name" in event and event["name"]:
        name_fact = actapi.fact("name", strip_special_chars(event["name"]))
        name_fact.source("report", report_id)
        act.api.helpers.handle_fact(name_fact, output_format="json")

    # iterate over all indicators
    for ioc in event["indicators"]:

        if not ioc["type"] in OTX_ACT_TYPE_MAPPING:
            continue

        # identify act fact type
        act_type: Text = OTX_ACT_TYPE_MAPPING[ioc["type"]]

        # add schemas for certain ioc types
        if ioc["type"] == "email":
            ioc["indicator"] = f'email://{ioc["indicator"]}'
        elif ioc["type"] == "FilePath":
            ioc["indicator"] = f'file://{ioc["indicator"]}'

        # special treatment for uri's
        if act_type in ["uri"]:
            act.api.helpers.handle_uri(actapi, ioc["indicator"], output_format="json")
        else:
            # create fact
            if "description" in ioc and ioc["description"]:
                fact = actapi.fact(
                    "mentions", comment=strip_special_chars(ioc["description"])
                )
            else:
                fact = actapi.fact("mentions")

            fact.source("report", report_id)

            # some facts should not be lower cased
            # uri is handled above, but added for safety
            if act_type in ["mutex", "uri"]:
                fact.destination(act_type, ioc["indicator"])
            else:
                fact.destination(act_type, ioc["indicator"].lower())

            # output fact
            act.api.helpers.handle_fact(fact, output_format="json")

            # if fact type is a hash, we also have to create a fact which tells us what kind
            # of hash it represents
            if act_type in ["hash"]:
                hash_type: Text = ioc["type"].split("-")[-1].lower()
                hash_fact = actapi.fact("category", hash_type)
                hash_fact.source(act_type, ioc["indicator"])
                act.api.helpers.handle_fact(hash_fact, output_format="json")


def main() -> None:
    """Main function"""
    # Look for default ini file in "/etc/actworkers.ini" and
    # ~/config/actworkers/actworkers.ini (or replace .config with
    # $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    # setup logging
    act.api.utils.setup_logging(args.loglevel, prefix="act-alienvault-otx")

    # check necessary configuration items for errors
    for item in ["config_path", "otx_baseurl", "otx_apikey", "otx_path_lastretrived"]:
        if item not in args:
            raise ConfigurationError("Missing configuration item {}".format(item))

    # initialise act api
    actapi = worker.init_act(args)

    # initialise otx api
    otxapi = AlienvaultOTXAPI(args)

    # create facts for indicators in each event
    for event in otxapi.get_subscribed():
        handle_facts(actapi, event)


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        with pid.PidFile(force_tmpdir=True, pidname="act-alienvault-otx.pid"):
            main()
    except Exception:
        logging.error("Unhandled exception: %s", traceback.format_exc())
        raise


if __name__ == "__main__":
    main_log_error()
