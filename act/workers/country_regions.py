#!/usr/bin/env python3

"""
Worker module fetching ISO 3166 from github to add facts for:
   country -memberOf-> subRegion
   subRegion -memberOf-> region

If --act-baseurl and --userid is specified, add the facts to the platform.
If not, print facts to stdout.
"""


import argparse
import traceback
from logging import error, warning
from typing import Dict, List

import act.api
from act.workers.libs import worker, config
from act.api.helpers import handle_fact


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Country/region enrichment')
    parser.add_argument('--country-region-url', dest='country_region_url',
                        default="https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json",
                        help="Country region URL in json format")

    return parser


def process(actapi: act.api.Act, country_list: List[Dict[str, str]]) -> None:
    """
    Loop over all ISO-3166 countries and construct facts for
    county -memberOf-> subRegion and subRegion -memberOf-> region.
    """

    for c_map in country_list:
        country_name = c_map["name"]
        sub_region = c_map["sub-region"]
        region = c_map["region"]

        if country_name and sub_region:
            handle_fact(
                actapi.fact("memberOf")
                .source("country", country_name)
                .destination("subRegion", sub_region)
            )
        else:
            warning("Missing name or sub-region: {}".format(c_map))

        if sub_region and region:
            handle_fact(
                actapi.fact("memberOf")
                .source("subRegion", sub_region)
                .destination("region", region)
            )
        else:
            warning("Missing sub-region or region: {}".format(c_map))


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = config.handle_args(parseargs(), "actworkers", "actworkers.ini", "country-regions")

    try:
        process(
            act.api.Act(args.act_baseurl, args.user_id, args.loglevel, args.logfile, "country-region"),
            worker.fetch_json(args.country_region_url, args.proxy_string, args.timeout)
        )
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
