#!/usr/bin/env python3

"""
Thaicert worker for the ACT platform

"""


from logging import error

import argparse
import sys
import traceback
import act
import act.api
from typing import Text, Dict, List
from itertools import combinations

from act.workers.libs import worker
from act.api.helpers import handle_fact


WORKER_NAME = "thaicert"
THAICERT_URL = "https://apt.thaicert.or.th/cgi-bin/getcard.cgi?g=all&o=j"

def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments"""
    parser = worker.parseargs("ThaiCERT worker")
    parser.add_argument('--url', dest="thaicert_url", default=THAICERT_URL,
                        help='ThaiCERT data URL')
    return parser


def add_ta(client: act.api.Act, ta_cards: List, output_format: Text = "json") -> None:
    for actor in ta_cards:
        if len(actor["names"]) > 1:
            aliases = list(set([alias["name"] for alias in actor["names"]]))
            for a1, a2 in combinations(aliases, 2):
                handle_fact(
                    client.fact("alias")
                    .bidirectional("threatActor", a1, "threatActor", a2),
                    output_format=output_format
                )

        if "tools" in actor:
            for tool in actor["tools"]:
                chain = act.api.fact.fact_chain(
                    client.fact("classifiedAs")
                    .source("content", "*")
                    .destination("tool", tool.lower()),
                    client.fact("observedIn")
                    .source("content", "*")
                    .destination("event", "*"),
                    client.fact("attributedTo")
                    .source("event", "*")
                    .destination("incident", "*"),
                    client.fact("attributedTo")
                    .source("incident", "*")
                    .destination("threatActor", actor["actor"])
                )

            for fact in chain:
                handle_fact(fact, output_format=output_format)

        if "observed-countries" in actor:
            for country in actor["observed-countries"]:
                chain = act.api.fact.fact_chain(
                    client.fact("locatedIn")
                    .source("organization", "*")
                    .destination("country", country),
                    client.fact("targets")
                    .source("incident", "*")
                    .destination("organization", "*"),
                    client.fact("attributedTo")
                    .source("incident", "*")
                    .destination("threatActor", actor["actor"])
                )

            for fact in chain:
                handle_fact(fact, output_format=output_format)

        if "observed-sectors" in actor:
            for sector in actor["observed-sectors"]:
                chain = act.api.fact.fact_chain(
                    client.fact("memberOf")
                    .source("organization", "*")
                    .destination("sector", sector),
                    client.fact("targets")
                    .source("incident", "*")
                    .destination("organization", "*"),
                    client.fact("attributedTo")
                    .source("incident", "*")
                    .destination("threatActor", actor["actor"])
                )
                for fact in chain:
                    handle_fact(fact, output_format=output_format)

        if "operations" in actor:
            for operation in actor["operations"]:
                chain = act.api.fact.fact_chain(
                    client.fact("attributedTo")
                    .source("incident", "*")
                    .destination("campaign", operation["activity"].split("\n")[0]),
                    client.fact("attributedTo")
                    .source("incident", "*")
                    .destination("threatActor", actor["actor"])
                )
        if "country" in actor:
            for country in actor["country"]:
                chain = act.api.fact.fact_chain(
                    client.fact("locatedIn")
                    .source("organization", "*")
                    .destination("country", country),
                    client.fact("attributedTo")
                    .source("threatActor", actor["actor"])
                    .destination("organization", "*")
                )

def main() -> None:
    """Main function"""
    args = worker.handle_args(parseargs())
    actapi = worker.init_act(args)
    thaicert_cards = worker.fetch_json(args.thaicert_url, args.proxy_string, args.http_timeout)
    add_ta(actapi, thaicert_cards["values"])


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
