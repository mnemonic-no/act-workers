#!/usr/bin/env python3

"""
Threat Actor Helper worker

Create common placeholders based on known information.

"""

import argparse
import functools
import sys
import traceback
from logging import error
from typing import Dict, List, Text

import act.api
from act.api.helpers import Act, handle_fact
from pyattck import Attck

from act.workers.libs import worker


def split_arg(argument, delimiter=","):
    """ Split argument with delimiter and return list """
    if not argument:
        return []

    return [arg.strip() for arg in argument.split(delimiter) if arg]


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Threat Actor helper')
    parser.add_argument('--ta', '--threat-actor', help='Threat Actor')
    parser.add_argument('--ta-located-in', help='Threat Actor located in')
    parser.add_argument('--campaign', help='Campaign')
    parser.add_argument('--techniques', type=split_arg, help='Techniques (Commaseparated list)')
    parser.add_argument('--tools', type=split_arg, help='Tools (Commaseparated list)')
    parser.add_argument('--sectors', type=split_arg, help='Sectors (Commaseparated list)')
    parser.add_argument('--target-countries', type=split_arg, help='Target Countries (Commaseparated list)')
    parser.add_argument('--country-region-url',
                        default="https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json",
                        help="Country region URL in json format")

    parser.add_argument(
        '--sector-vocabulary',
        type=split_arg,
        default="aerospace, agriculture, automotive, chemical, commercial, communications, construction, dams, defense,"
        "education, emergency-services, energy, entertainment, financial-services, government, government-local,"
        "government-national, government-public-services, government-regional, healthcare, hospitality-leisure,"
        "infrastructure, insurance, manufacturing, mining, non-profit, nuclear, pharmaceuticals, retail, technology,"
        "telecommunications, transportation, utilities, water",
        help="Sector vocabulary")

    return parser


def levenshtein(a: Text, b: Text) -> int:
    "Calculates the Levenshtein distance between a and b."

    n, m = len(a), len(b)
    if n > m:
        # Make sure n <= m, to use O(min(n,m)) space
        a, b = b, a
        n, m = m, n

    current = list(range(n + 1))
    for i in range(1, m + 1):
        previous, current = current, [i] + [0] * n
        for j in range(1, n + 1):
            add, delete = previous[j] + 1, current[j - 1] + 1
            change = previous[j - 1]
            if a[j - 1] != b[i - 1]:
                change = change + 1
            current[j] = min(add, delete, change)

    return current[n]


def find_levenshtein_candiates(value, vocabulary, n_items=3):
    "Return top N list of possible levenshtein candidates"

    possible_match = []

    for entry in set(vocabulary):
        possible_match.append([levenshtein(value, entry), entry])

    return [x[1] for x in sorted(possible_match)[:n_items] if x[1]]


@functools.lru_cache(32)
def fetch_country_regions(country_region_url: Text, proxy_string: Text, http_timeout: int):
    "Fetch ISO-3166 list of country/regions"

    vocabulary: Dict = {}

    for c_map in worker.fetch_json(country_region_url, proxy_string, http_timeout):
        country = c_map["name"]
        vocabulary[country.lower()] = country

    return vocabulary


@functools.lru_cache(32)
def mitre_techniques():
    """
    Get list of all MITRE ATT&CK techniques and return map combined with
    both technique IDs and (lowercased) name as key an name as value
    """

    attack = Attck()
    techniques = {}

    for technique in attack.enterprise.techniques:
        techniques[technique.id] = technique.name
        techniques[technique.name.lower()] = technique.name

    return techniques


def technique_lookup_or_die(technique: Text):
    "Lookup technique and return name if exists, otherwise die with suggestion of correct name"
    techniques = mitre_techniques()

    if technique in techniques:
        return techniques[technique]

    else:
        sys.stderr.write(f"ERROR: Unable to find technique: {technique}\n")
        sys.stderr.write(f"Did you mean any of these techniques? \n")
        for candidate in find_levenshtein_candiates(technique, techniques.keys()):
            sys.stderr.write(f"* {candidate}\n")

        sys.exit(1)


def country_lookup_or_die(args: argparse.Namespace, country: Text):
    "Lookup country and return name if exists, otherwise die with suggestion of correct name"
    vocabulary = fetch_country_regions(args.country_region_url, args.proxy_string, args.http_timeout)

    if country.lower() in vocabulary:
        return vocabulary[country.lower()]

    else:
        sys.stderr.write(f"ERROR: Unable to find country in ISO 3166 list: {country}\n")
        sys.stderr.write(f"Did you mean any of these countries? \n")
        for candidate in find_levenshtein_candiates(country, vocabulary.values()):
            sys.stderr.write(f"* {candidate}\n")

        sys.exit(1)

def sector_lookup_or_die(vocabulary: List[Text], sector: Text):
    "Lookup sector and return name if exists, otherwise die with suggestion of correct name"

    if sector.lower() in vocabulary:
        return sector.lower()

    else:
        sys.stderr.write(f"ERROR: Unable to find sector in vocabulary: {sector}\n")
        sys.stderr.write(f"Did you mean any of these sectors? \n")
        for candidate in find_levenshtein_candiates(sector, vocabulary):
            sys.stderr.write(f"* {candidate}\n")

        sys.exit(1)


def add_ta_techniques(client: Act, output_format: Text, threat_actor: Text, techniques: List[Text]):
    """ Threat Actor Techniques """

    for technique in techniques:
        chain = act.api.fact.fact_chain(
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor),
            client.fact("attributedTo")
            .source("event", "*")
            .destination("incident", "*"),
            client.fact("classifiedAs")
            .source("event", "*")
            .destination("technique", technique_lookup_or_die(technique))
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_tools(client: Act, output_format: Text, threat_actor: Text, tools: List[Text]):
    """ Threat Actor Tools """

    for tool in tools:
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
            .destination("threatActor", threat_actor)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_sectors(client: Act, output_format: Text, threat_actor: Text, sectors: List[Text], vocabulary: List[Text]):
    for sector in sectors:
        chain = act.api.fact.fact_chain(
            client.fact("targets")
            .source("incident", "*")
            .destination("organization", "*"),
            client.fact("memberOf")
            .source("organization", "*")
            .destination("sector", sector_lookup_or_die(vocabulary, sector)),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_target_country(args: argparse.Namespace, client: Act, output_format: Text, threat_actor: Text, target_countries: List[Text]):
    for target_country in target_countries:
        chain = act.api.fact.fact_chain(
            client.fact("targets")
            .source("incident", "*")
            .destination("organization", "*"),
            client.fact("locatedIn")
            .source("organization", "*")
            .destination("country", country_lookup_or_die(args, target_country)),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_located_in(args: argparse.Namespace, client: Act, output_format: Text, threat_actor: Text, located_in: Text):
    chain = act.api.fact.fact_chain(
        client.fact("locatedIn")
        .source("organization", "*")
        .destination("country", country_lookup_or_die(args, located_in)),
        client.fact("attributedTo")
        .source("threatActor", threat_actor)
        .destination("organization", "*")
    )

    for fact in chain:
        handle_fact(fact, output_format=output_format)


def add_ta_campaign(client: Act, output_format: Text, threat_actor: Text, campaign: Text):
    chain = act.api.fact.fact_chain(
        client.fact("attributedTo")
        .source("incident", "*")
        .destination("campaign", campaign),
        client.fact("attributedTo")
        .source("incident", "*")
        .destination("threatActor", threat_actor)
    )

    for fact in chain:
        handle_fact(fact, output_format=output_format)


def main() -> None:
    """ Main function """

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not args.ta:
        sys.stderr.write("You must specify Threat Actor with --ta <THREAT ACTOR>\n")
        sys.exit(1)

    if args.target_countries:
        add_ta_target_country(args, actapi, args.output_format, args.ta, args.target_countries)

    if args.campaign:
        add_ta_campaign(actapi, args.output_format, args.ta, args.campaign)

    if args.tools:
        add_ta_tools(actapi, args.output_format, args.ta, args.tools)

    if args.techniques:
        add_ta_techniques(actapi, args.output_format, args.ta, args.techniques)

    if args.sectors:
        add_ta_sectors(actapi, args.output_format, args.ta, args.sectors, args.sector_vocabulary)

    if args.ta_located_in:
        add_ta_located_in(args, actapi, args.output_format, args.ta, args.ta_located_in)


def main_log_error() -> None:
    "Call main() and log all excetions  as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
