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

import act
import worker
from act.helpers import handle_fact


def parseargs() -> argparse.Namespace:
    """ Parse arguments """
    parser = worker.parseargs('Country/region enrichment')
    parser.add_argument('--country-region-url', dest='country_region_url',
                        default="https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json",
                        help="Country region URL in json format")

    return parser.parse_args()


def process(actapi: act.Act, country_list: List[Dict[str, str]]) -> None:
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


if __name__ == '__main__':
    ARGS = parseargs()

    try:
        process(
            act.Act(ARGS.act_baseurl, ARGS.user_id, ARGS.loglevel, ARGS.logfile, "country-region"),
            worker.fetch_json(ARGS.country_region_url, ARGS.proxy_string, ARGS.timeout)
        )
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise
