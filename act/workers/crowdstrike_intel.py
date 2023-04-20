#!/usr/bin/env python3

"""
Worker module for fetch new intel from CrowdStrike Intel pro (requires license from CrowdStrike)

If --act-baseurl and --userid is specified, add the facts to the platform.
If not, print facts to stdout.
"""


import traceback
from datetime import datetime, timedelta
from logging import debug, error, info, warning
from typing import Any, Callable, Dict, Optional

import act.api
import caep
from act.api.helpers import handle_fact, handle_uri
from act.api.libs import cli
from falconpy import Intel
from pydantic import BaseModel, Field

from act.workers.libs import crowdstrike_intel, fact_chain, worker

COUNTRY_REGIONS = "https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json"


class Config(worker.WorkerConfig):
    id: str = Field(description="API Client ID")
    secret: str = Field(description="API Client Secret")


class Objects(BaseModel):
    content: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    uri: Optional[str] = None


# Mapping from Crowdstrike Target Vocabulary
# to Stix industry sector.
# Not all targets can be mapped
TARGET_SECTOR_MAP = {
    "Target/Aerospace": "aerospace",
    "Target/Agricultural": "agriculture",
    "Target/Chemical": "chemical",
    "Target/Defense": "defence",
    "Target/Dissident": "",
    "Target/Energy": "energy",
    "Target/Extractive": "mining",
    "Target/Financial": "financial-services",
    "Target/Government": "government-national",
    "Target/Healthcare": "healthcare",
    "Target/Insurance": "insurance",
    "Target/InternationalOrganizations": "",
    "Target/Legal": "",
    "Target/Manufacturing": "manufacturing",
    "Target/Media": "infrastructure",
    "Target/NGO": "",
    "Target/Pharmaceutical": "pharmaceuticals",
    "Target/Research": "",
    "Target/Retail": "retail",
    "Target/Shipping": "",
    "Target/Technology": "techonology",
    "Target/Telecom": "telecommunications",
    "Target/Transportation": "telecommunications",
    "Target/Universities": "education",
}


# Other types that can be handled in the future:
# email_address
# file_name
# password
# persona_name
# username

type_map: Dict[str, Callable[[crowdstrike_intel.Indicator], Dict[str, Any]]] = {
    "hash_sha256": lambda x: {"content": x.indicator},
    "hash_sha1": lambda x: {"hash_sha1": x.indicator},
    "hash_md5": lambda x: {"hash_md5": x.indicator},
    "url": lambda x: {"uri": x.indicator},
    "domain": lambda x: {"uri": f"network://{x.indicator}"},
    "ip_address": lambda x: {"uri": f"network://{x.indicator}"},
}


def expand_objects(indicator: crowdstrike_intel.Indicator) -> Optional[Objects]:
    """Convert CrowdStrike indicator to a class that represents content, hash and URI"""

    # Set type, based on map
    obj_type = type_map.get(indicator.type)

    # Unknown type, skip indicator
    if not obj_type:
        return None

    obj_parameters = obj_type(indicator)

    obj = Objects(**obj_parameters)

    # Set hash/content values based on relations defined in indicator
    for rel in indicator.relations:
        if rel.type == "hash_sha256":
            obj.content = rel.indicator

        elif rel.type == "hash_sha1":
            obj.hash_sha1 = rel.indicator

        elif rel.type == "hash_md5":
            obj.hash_md5 = rel.indicator

    return obj


def handle_hash_content_uri(
    actapi: act.api.Act,
    indicator: crowdstrike_intel.Indicator,
    obj: Objects,
    output_format: str = "json",
) -> None:
    """
    Handle all facts between hash, content and uri:
        (hash) -represents-> (content)
        (content) -at-> (uri)
        (content) -connectsTo-> (uri)
        (...) -componentOf-> (uri)
    """

    # If we have C2 in kill chain, we can use `connectsTo`, otherwize we use `at`
    content_uri_fact_type = "connectsTo" if ("c2" in indicator.kill_chains) else "at"

    handle_fact(
        actapi.fact(content_uri_fact_type)
        .source("content", obj.content)
        .destination("uri", obj.uri),
        output_format=output_format,
    )

    # Expand URI with all components
    handle_uri(actapi, obj.uri, output_format=output_format)

    # (hash) represents (content)
    handle_fact(
        actapi.fact("represents")
        .source("hash", obj.content)
        .destination("content", obj.content),
        output_format=output_format,
    )

    if obj.hash_sha1:
        handle_fact(
            actapi.fact("represents")
            .source("hash", obj.hash_sha1)
            .destination("content", obj.content),
            output_format=output_format,
        )

    if obj.hash_md5:
        handle_fact(
            actapi.fact("represents")
            .source("hash", obj.hash_md5)
            .destination("content", obj.content),
            output_format=output_format,
        )


def handle_indicator(
    actapi: act.api.Act,
    indicator: crowdstrike_intel.Indicator,
    output_format: str = "json",
) -> None:
    """
    Handle Indicators received from CrowdStrike Intel API
    We only add facts if we have content and uri
    """

    obj = expand_objects(indicator)

    if not obj:
        # No extracted objects
        return

    if not (obj.uri and obj.content):
        # Do not handle indicators that do not have an URL (domain/fqdn is handled as URLs
        # using network://<ip> and network://<fqdn>)
        # We might extend this later, but there is a large amount indicators where we only
        # have a hash
        return

    handle_hash_content_uri(actapi, indicator, obj)

    for vuln in indicator.vulnerabilities:
        handle_fact(
            actapi.fact("exploits")
            .source("content", obj.content)
            .destination("vulnerability", vuln),
            output_format=output_format,
        )

    for malware_family in indicator.malware_families:
        handle_fact(
            actapi.fact("classifiedAs")
            .source("content", obj.content)
            .destination("tool", malware_family),
            output_format=output_format,
        )

    for actor in indicator.actors:
        fact_chain.handle_ta_uri(
            actapi,
            output_format,
            actor,
            obj.uri,
        )

        for label in indicator.labels:
            sector = TARGET_SECTOR_MAP.get(label.name)

            if sector:
                fact_chain.handle_ta_sectors(actapi, output_format, actor, [sector])


def get_last_indicator() -> str:
    "Get last update from disk (~/.cache/<worker_name>/last_update)"
    cache_filename = (
        caep.get_cache_dir("crowdstrike_intel", create=True) / "latest_indicator"
    )

    if cache_filename.exists():
        # Read last_update from last recorded succsfully recieved event
        with open(cache_filename) as f:
            last_indicator = f.read().strip()
            debug("last update starting at {}".format(last_indicator))
    else:
        # last_update not specified, set to now-3d
        last_indicator = str((datetime.now() - timedelta(days=3)).timestamp())

        info("last update not specified, autoconfigured as {}".format(last_indicator))

    return last_indicator


def update_last_indicator(marker: str) -> None:
    "Write last update from disk (~/.cache/<worker_name>/last_update)"
    cache_filename = (
        caep.get_cache_dir("crowdstrike_intel", create=True) / "latest_indicator"
    )

    # Write last update timestamp to disk
    with open(cache_filename, "w") as f:
        f.write(marker)


def process_indicators(actapi: act.api.Act, args: Config, falcon: Intel) -> None:
    """
    Loop over new indicators
    """

    indicator_marker = None

    for indicator in crowdstrike_intel.get_latest_indicators(
        falcon, get_last_indicator()
    ):
        handle_indicator(actapi, indicator, args.output_format)

        indicator_marker = indicator.marker

    if indicator_marker:
        update_last_indicator(indicator_marker)


def handle_actor(
    actapi: act.api.Act,
    actor: crowdstrike_intel.Actor,
    countries: Dict[str, str],
    output_format: str = "json",
) -> None:
    """
    Handle Actors received from CrowdStrike Intel API
    """

    # Alias facts
    for alias in actor.known_as:
        handle_fact(
            actapi.fact("alias").bidirectional(
                "threatActor", actor.name, "threatActor", alias
            )
        )

    for country in actor.target_countries:
        cc = country.slug.upper()
        if cc in countries:
            fact_chain.handle_ta_target_country(
                actapi, output_format, actor.name, [countries[cc]]
            )
        else:
            warning(f"Target country code `{cc}` is not in ISO-3166")


def process_actors(actapi: act.api.Act, args: Config, falcon: Intel) -> None:
    """
    Loop over new indicators
    """

    # Get ISO3166 map from country code -> name
    countries: Dict[str, str] = {}

    debug(f"Fetching ISO-3166 data (proxy={args.proxy_string})")

    for country in worker.fetch_json(
        COUNTRY_REGIONS, args.proxy_string, args.http_timeout
    ):
        countries[country["alpha-2"].upper()] = country["name"]

    for actor in crowdstrike_intel.get_actors(falcon):
        handle_actor(actapi, actor, countries, args.output_format)


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    # args = cli.handle_args(parseargs())
    args: Config = cli.load_config(Config, "CrowdStrike Intel")

    actapi = worker.init_act(args)

    falcon = Intel(
        client_id=args.id,
        client_secret=args.secret,
        proxy={"https": args.proxy_string} if args.proxy_string else None,
    )

    try:
        process_actors(actapi, args, falcon)
    except Exception:
        error(
            "Unhandled exception in process_actors: {}".format(traceback.format_exc())
        )

    try:
        process_indicators(actapi, args, falcon)
    except Exception:
        error(
            "Unhandled exception in process_indicators: {}".format(
                traceback.format_exc()
            )
        )


if __name__ == "__main__":
    main_log_error()
