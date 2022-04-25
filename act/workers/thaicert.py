#!/usr/bin/env python3

"""
Thaicert worker for the ACT platform

"""

import argparse
import traceback
from collections import defaultdict
from itertools import combinations
from logging import error, warning
from typing import List, Text

import act.api
from act.api.helpers import handle_fact, handle_facts
from act.api.libs import cli

import act
from act.workers.libs import worker

WORKER_NAME = "thaicert"
THAICERT_URL = "https://apt.thaicert.or.th/cgi-bin/getcard.cgi?g=all&o=j"
STIX_VOCAB = "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/sdos/identity.json"
COUNTRY_REGIONS = "https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json"
THAICERT_TOOLS_URL = "https://apt.thaicert.or.th/cgi-bin/getcard.cgi?t=all&o=j"


def parseargs() -> argparse.ArgumentParser:
    """Parse arguments"""
    parser = worker.parseargs("ThaiCERT worker")
    parser.add_argument(
        "--url", dest="thaicert_url", default=THAICERT_URL, help="ThaiCERT data URL"
    )
    return parser


def process(client: act.api.Act, ta_cards: List, output_format: Text = "json") -> None:
    "Extract threat actor cards from ThaiCERT"

    # Keep list of names with an alias points to
    # There should only be one to have a meaningfull alias
    ta_alias_names = defaultdict(set)
    ta_aliases = {}

    for actor in ta_cards:
        ta_name = actor["names"][0]["name"]

        ta_aliases[ta_name] = []

        for alias in actor["names"][1:]:
            alias_name = alias["name"]

            # names might be identical after format/normalization
            if ta_name == alias_name:
                continue

            ta_alias_names[alias_name].add(ta_name)
            ta_aliases[ta_name].append(alias_name)

    for ta_name in ta_aliases:
        for alias_name in ta_aliases[ta_name]:

            # This alias is mentioned for multiple main threat
            # actors so we skip this alias
            if len(ta_alias_names[alias_name]) > 1:
                warning(
                    f"Skipping TA alias {alias_name} <-> {ta_name} since {alias_name} is alias for multiple names: {ta_alias_names[alias_name]}"
                )
                continue

            handle_fact(
                client.fact("alias").bidirectional(
                    "threatActor", ta_name, "threatActor", alias_name
                ),
                output_format=output_format,
            )

    for actor in ta_cards:
        if "operations" in actor:
            for operation in actor["operations"]:
                if len(operation["activity"].split("\n")[0].split()) < 4:
                    for ta in actor["actor"].split(","):
                        handle_facts(
                            act.api.fact.fact_chain(
                                client.fact("attributedTo")
                                .source("incident", "*")
                                .destination(
                                    "campaign", operation["activity"].split("\n")[0]
                                ),
                                client.fact("attributedTo")
                                .source("incident", "*")
                                .destination("threatActor", ta),
                            ),
                            output_format=output_format,
                        )


def add_countries(
    client: act.api.Act, ta_cards: List, countries: List, output_format: Text = "json"
) -> None:
    """
    Only submit country if ISO-3166 country
    """
    for actor in ta_cards:
        if "country" in actor:
            for country in actor["country"]:
                if country.lower() in countries:
                    handle_facts(
                        act.api.fact.fact_chain(
                            client.fact("locatedIn")
                            .source("organization", "*")
                            .destination("country", country),
                            client.fact("attributedTo")
                            .source("threatActor", actor["actor"])
                            .destination("organization", "*"),
                        ),
                        output_format=output_format,
                    )

        if "observed-countries" in actor:
            for country in actor["observed-countries"]:
                if country.lower() in countries:
                    for ta in actor["actor"].split(","):
                        handle_facts(
                            act.api.fact.fact_chain(
                                client.fact("locatedIn")
                                .source("organization", "*")
                                .destination("country", country),
                                client.fact("targets")
                                .source("incident", "*")
                                .destination("organization", "*"),
                                client.fact("attributedTo")
                                .source("incident", "*")
                                .destination("threatActor", ta),
                            ),
                            output_format=output_format,
                        )


def add_sectors(
    client: act.api.Act, ta_cards: List, vocab: List, output_format: Text = "json"
) -> None:
    """
    Only submit sectors if in STIX vocabulary
    """
    for actor in ta_cards:
        if "observed-sectors" in actor:
            for sector in actor["observed-sectors"]:
                if sector.lower() in vocab["definitions"]["industry-sector-ov"]["enum"]:
                    for ta in actor["actor"].split(","):
                        handle_facts(
                            act.api.fact.fact_chain(
                                client.fact("memberOf")
                                .source("organization", "*")
                                .destination("sector", sector.lower()),
                                client.fact("targets")
                                .source("incident", "*")
                                .destination("organization", "*"),
                                client.fact("attributedTo")
                                .source("incident", "*")
                                .destination("threatActor", ta),
                            ),
                            output_format=output_format,
                        )


def add_tools(
    client: act.api.Act, ta_cards: List, tools: List, output_format: Text = "json"
) -> None:
    """
    Submit tool aliases and actor tools
    """
    tool_vocab = [tool["tool"] for tool in tools]
    for actor in ta_cards:
        if "tools" in actor:
            for tool in actor["tools"]:
                if tool in tool_vocab:
                    for ta in actor["actor"].split(","):
                        handle_facts(
                            act.api.fact.fact_chain(
                                client.fact("classifiedAs")
                                .source("content", "*")
                                .destination("tool", tool),
                                client.fact("observedIn")
                                .source("content", "*")
                                .destination("incident", "*"),
                                client.fact("attributedTo")
                                .source("incident", "*")
                                .destination("threatActor", ta),
                            ),
                            output_format=output_format,
                        )

    for values in tools:
        aliases = set(
            [tool["name"].strip() for tool in values["names"]] + [values["tool"]]
        )
        for tool1, tool2 in combinations(aliases, 2):

            if tool1 == tool2:
                continue

            fact = client.fact("alias").bidirectional("tool", tool1, "tool", tool2)
            handle_fact(fact)


def main() -> None:
    """Main function"""
    args = cli.handle_args(parseargs())
    actapi = worker.init_act(args)
    ta_cards = worker.fetch_json(
        args.thaicert_url, args.proxy_string, args.http_timeout
    )
    process(actapi, ta_cards["values"])

    vocab = worker.fetch_json(STIX_VOCAB, args.proxy_string, args.http_timeout)
    add_sectors(actapi, ta_cards["values"], vocab)

    countries = worker.fetch_json(COUNTRY_REGIONS, args.proxy_string, args.http_timeout)
    countries = [country["name"].lower() for country in countries]
    add_countries(actapi, ta_cards["values"], countries)

    tools = worker.fetch_json(THAICERT_TOOLS_URL, args.proxy_string, args.http_timeout)
    add_tools(actapi, ta_cards["values"], tools["values"])


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
