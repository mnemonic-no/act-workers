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
from act.api.helpers import Act, handle_facts
from act.api.libs import cli
from pyattck import Attck

from act.workers import worker_config
from act.workers.libs import worker


class VocabularyException(Exception):
    pass


def parseargs() -> argparse.ArgumentParser:
    """Parse arguments"""
    parser = worker.parseargs("Threat Actor helper")
    parser.add_argument("--ta", "--threat-actor", help="Threat Actor")
    parser.add_argument("--ta-located-in", help="Threat Actor located in")
    parser.add_argument("--campaign", help="Campaign")
    parser.add_argument(
        "--techniques",
        type=worker_config.string_list,
        default=[],
        help="Techniques (Commaseparated list)",
    )
    parser.add_argument(
        "--tools",
        type=worker_config.string_list,
        default=[],
        help="Tools (Commaseparated list)",
    )
    parser.add_argument(
        "--sectors",
        type=worker_config.string_list,
        default=[],
        help="Sectors (Commaseparated list)",
    )
    parser.add_argument(
        "--target-countries",
        type=worker_config.string_list,
        default=[],
        help="Target Countries (Commaseparated list)",
    )
    parser.add_argument(
        "--country-region",
        default="https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json",
        help="Country region in json format (HTTP URL or file)",
    )

    # Stix Vocabulary
    parser.add_argument(
        "--sector-vocabulary",
        default="https://raw.githubusercontent.com/mnemonic-no/act-scio2/master/act/scio/etc/plugins/sectors.cfg",
        help="Sector vocabulary (STIX2, in scio format). Fetched from URL or file",
    )

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


def find_levenshtein_candiates(value: Text, vocabulary: List, n_items: int = 3) -> List:
    "Return top N list of possible levenshtein candidates"

    possible_match = []

    for entry in set(vocabulary):
        possible_match.append([levenshtein(value, entry), entry])

    return [x[1] for x in sorted(possible_match)[:n_items] if x[1]]


@functools.lru_cache(32)
def fetch_country_regions(
    country_region: Text, proxy_string: Text, http_timeout: int
) -> Dict[Text, Text]:
    "Fetch ISO-3166 list of country/regions"

    vocabulary: Dict = {}

    for c_map in worker.fetch_json(country_region, proxy_string, http_timeout):
        country = c_map["name"]
        vocabulary[country.lower()] = country

    return vocabulary


@functools.lru_cache(32)
def fetch_sector(
    sector_vocabulary: Text, proxy_string: Text, http_timeout: int
) -> Dict[Text, Text]:
    "Fetch STIX2 sector vocabulary"

    vocabulary: Dict = {}

    # format=
    # name: alias1,alias2,...aliasN
    for line in worker.fetch(sector_vocabulary, proxy_string, http_timeout).split("\n"):
        if not line.strip():
            continue

        name, aliases = line.split(":", 1)

        vocabulary[name] = name

        for alias in [a.strip() for a in aliases.split(",")]:
            vocabulary[alias] = name

    return vocabulary


@functools.lru_cache(32)
def mitre_techniques() -> Dict[Text, Text]:
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


def technique_lookup(technique: Text) -> Text:
    "Lookup technique and return name if exists, otherwise raise VocabularyException"
    techniques = mitre_techniques()

    try:
        return techniques[technique]
    except KeyError:
        raise VocabularyException(
            "Technique {} not found in MITRE ATT&CK. Nearest matches: {}".format(
                technique,
                ", ".join(find_levenshtein_candiates(technique, techniques.keys())),
            )
        )


def country_lookup(args: argparse.Namespace, country: Text) -> Text:
    "Lookup country and return name if exists, otherwise raise VocabularyException"
    vocabulary = fetch_country_regions(
        args.country_region, args.proxy_string, args.http_timeout
    )

    try:
        return vocabulary[country.lower()]
    except KeyError:
        raise VocabularyException(
            "Country {} not found in ISO 3166 database. Nearest matches: {}".format(
                country,
                ", ".join(find_levenshtein_candiates(country, vocabulary.values())),
            )
        )


def sector_lookup(args: argparse.Namespace, sector: Text) -> Text:
    "Lookup sector and return name if exists, otherwise raise VocabularyException"

    vocabulary = fetch_sector(
        args.sector_vocabulary, args.proxy_string, args.http_timeout
    )

    try:
        return vocabulary[sector.lower()]
    except KeyError:
        raise VocabularyException(
            "Sector {} not found in Stix vocabulary. Nearest matches: {}".format(
                sector, ", ".join(find_levenshtein_candiates(sector, vocabulary))
            )
        )


def add_ta_techniques(
    client: Act, output_format: Text, threat_actor: Text, techniques: List[Text]
) -> None:
    """Threat Actor Techniques"""

    for technique in techniques:
        handle_facts(
            act.api.fact.fact_chain(
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", threat_actor),
                client.fact("observedIn")
                .source("technique", technique)
                .destination("incident", "*"),
            ),
            output_format=output_format,
        )


def add_ta_tools(
    client: Act, output_format: Text, threat_actor: Text, tools: List[Text]
) -> None:
    """Threat Actor Tools"""

    for tool in tools:
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
                .destination("threatActor", threat_actor),
            ),
            output_format=output_format,
        )


def add_ta_sectors(
    client: Act, output_format: Text, threat_actor: Text, sectors: List[Text]
) -> None:
    """Threat Actor Sectors"""
    for sector in sectors:
        handle_facts(
            act.api.fact.fact_chain(
                client.fact("targets")
                .source("incident", "*")
                .destination("organization", "*"),
                client.fact("memberOf")
                .source("organization", "*")
                .destination("sector", sector),
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", threat_actor),
            ),
            output_format=output_format,
        )


def add_ta_target_country(
    client: Act, output_format: Text, threat_actor: Text, target_countries: List[Text]
) -> None:
    """Threat actor target countries"""
    for target_country in target_countries:
        handle_facts(
            act.api.fact.fact_chain(
                client.fact("targets")
                .source("incident", "*")
                .destination("organization", "*"),
                client.fact("locatedIn")
                .source("organization", "*")
                .destination("country", target_country),
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", threat_actor),
            ),
            output_format=output_format,
        )


def add_ta_located_in(
    client: Act, output_format: Text, threat_actor: Text, located_in: Text
) -> None:
    """Threat actor located in"""
    handle_facts(
        act.api.fact.fact_chain(
            client.fact("locatedIn")
            .source("organization", "*")
            .destination("country", located_in),
            client.fact("attributedTo")
            .source("threatActor", threat_actor)
            .destination("organization", "*"),
        ),
        output_format=output_format,
    )


def add_ta_campaign(
    client: Act, output_format: Text, threat_actor: Text, campaign: Text
) -> None:
    """Threat Actor Campaign"""
    handle_facts(
        act.api.fact.fact_chain(
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("campaign", campaign),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor),
        ),
        output_format=output_format,
    )


def main() -> None:
    """Main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not args.ta:
        sys.stderr.write("You must specify Threat Actor with --ta <THREAT ACTOR>\n")
        sys.exit(1)

    # Normalize and lookup country/technique/sectors
    # Print error with suggested match if not found
    ok = True

    try:
        args.target_countries = [
            country_lookup(args, country) for country in args.target_countries
        ]
    except (VocabularyException, FileNotFoundError, worker.UnsupportedScheme) as e:
        sys.stderr.write(str(e))
        ok = False

    try:
        args.techniques = [technique_lookup(tech) for tech in args.techniques]
    except VocabularyException as e:
        sys.stderr.write(str(e))
        ok = False

    try:
        if args.ta_located_in:
            args.ta_located_in = country_lookup(args, args.ta_located_in)
    except VocabularyException as e:
        sys.stderr.write(str(e))
        ok = False

    try:
        args.sectors = [sector_lookup(args, sector) for sector in args.sectors]
    except VocabularyException as e:
        sys.stderr.write(str(e))
        ok = False

    if not ok:
        sys.exit(1)

    if args.target_countries:
        add_ta_target_country(
            actapi, args.output_format, args.ta, args.target_countries
        )

    if args.campaign:
        add_ta_campaign(actapi, args.output_format, args.ta, args.campaign)

    if args.tools:
        add_ta_tools(actapi, args.output_format, args.ta, args.tools)

    if args.techniques:
        add_ta_techniques(actapi, args.output_format, args.ta, args.techniques)

    if args.sectors:
        add_ta_sectors(actapi, args.output_format, args.ta, args.sectors)

    if args.ta_located_in:
        add_ta_located_in(actapi, args.output_format, args.ta, args.ta_located_in)


def main_log_error() -> None:
    "Call main() and log all excetions  as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
