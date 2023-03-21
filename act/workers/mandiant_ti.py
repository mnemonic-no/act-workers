#!/usr/bin/env python3

"""
Worker module for Mandiant Threat Intelligence V4

If --act-baseurl and --userid is specified, add the facts to the platform.
If not, print facts to stdout.
"""


import traceback
from logging import error, warning
from typing import Any, Dict, List, Optional, cast

import act.api
from act.api.libs import cli
from pydantic import Field

from act.workers.libs import fact_chain, mandiant_ti_v4, worker

INDUSTRY_SECTOR_MAP = {
    "Manufacturing": "manufacturing",
    "Technology": "technology",
    "Governments": "government-national",
    "Financial Services": "financial-services",
    "Legal & Professional Services": "",
    "Telecommunications": "telecommunications",
    "Retail": "retail",
    "Construction & Engineering": "construction",
    "Media & Entertainment": "infrastructure",
    "Transportation": "transportation",
    "Healthcare": "healthcare",
    "Energy & Utilities": "energy",
    "Education": "education",
    "Chemicals & Materials": "manufacturing",
    "Hospitality": "hospitality-leisure",
    "Aerospace & Defense": "defence",
    "Insurance": "insurance",
    "Oil & Gas": "energy",
    "Pharmaceuticals": "pharmaceuticals",
    "Civil Society & Non-Profits": "non-profit",
    "Automotive": "automotive",
    "Agriculture": "agriculture",
}


class Config(worker.WorkerConfig):
    key: str = Field(description="API Key ID")
    secret: str = Field(description="API Secret")


def list_items(
    items: List[Dict[str, Any]],
    key: str = "name",
    lookup: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Lookup key in a list of dictionaries and return values

    >>> list_items([{"name": "x"}, {"name": "y"}, {"name": "z"}])
    ['x', 'y', 'z']
    """

    values = []

    for item in items:
        if key not in item:
            # Ignore if key not found
            continue

        value = lookup.get(item[key]) if lookup else item[key]

        if not value:
            continue

        values.append(value)

    return values


def handle_ta(actapi: act.api.Act, config: Config, ta: Dict[str, Any]) -> None:

    # TA -> SECTOR
    fact_chain.handle_ta_sectors(
        actapi,
        config.output_format,
        ta["name"],
        list_items(ta.get("industries", []), lookup=INDUSTRY_SECTOR_MAP),
    )

    # TA located IN country
    for country in list_items(ta.get("locations", {}).get("source", [])):
        fact_chain.handle_ta_located_in(
            actapi, config.output_format, ta["name"], country
        )

    # TA targets country
    fact_chain.handle_ta_target_country(
        actapi,
        config.output_format,
        ta["name"],
        list_items(ta.get("locations", {}).get("target", [])),
    )

    # TA uses malware
    fact_chain.handle_ta_tools(
        actapi,
        config.output_format,
        ta["name"],
        list_items(ta.get("malware", [])),
    )

    # TA uses tools (should we include this???)
    fact_chain.handle_ta_tools(
        actapi,
        config.output_format,
        ta["name"],
        list_items(ta.get("tools", [])),
    )


def handle_ta_attack_patterns(
    actapi: act.api.Act, config: Config, ta_attack_patterns: Dict[str, Any]
) -> None:

    # Get mapping from id to Name
    attack_id_name = {
        id: value["attack_pattern_identifier"]
        for id, value in ta_attack_patterns["attack-patterns"].items()
    }

    for ta in ta_attack_patterns["threat-actors"]:
        # TA uses tools (should we include this???)

        for tactics in ta["attack-patterns"].values():

            for tech in tactics:
                tech_id = attack_id_name.get(tech["id"])
                fact_chain.handle_ta_techniques(
                    actapi,
                    config.output_format,
                    ta["name"],
                    [cast(str, tech_id)],
                )

                for subtech in tech.get("sub_techniques", []):
                    subtech_id = attack_id_name.get(subtech["id"])
                    fact_chain.handle_ta_techniques(
                        actapi,
                        config.output_format,
                        ta["name"],
                        [cast(str, subtech_id)],
                    )


def process_threat_actors(
    actapi: act.api.Act,
    config: Config,
) -> None:
    """Loop over all threat actors"""

    # TODO: proxy?
    mandiant = mandiant_ti_v4.Connection(
        config.key, config.secret, proxy_string=config.proxy_string
    )

    tas = mandiant.get_threat_actors()

    ta_ids = [ta["id"] for ta in tas]

    handle_ta_attack_patterns(
        actapi, config, mandiant.get_threat_actors_attack_patterns(ta_ids)
    )

    for ta_id in ta_ids:
        try:
            handle_ta(actapi, config, mandiant.get_threat_actor(ta_id))
        except act.workers.libs.mandiant_ti_v4.V4APIError as err:
            warning(f"Unable to fetch threat actor {ta_id}: {err}")


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    # args = cli.handle_args(parseargs())
    args: Config = cli.load_config(Config, "Mandiant Threat Intelligence")

    actapi = worker.init_act(args)

    try:
        process_threat_actors(actapi, args)
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
