#!/usr/bin/env python3

"""Worker module fetching ISO 3166 from github to add is{Country,Region,SubRegion} facts,
output result in a format understandable to ACT add fact"""

import act
import worker

LOCATION_TYPE_M = {
    "name": "isCountry",
    "region": "isRegion",
    "sub-region": "isSubRegion"
}


def parseargs():
    """ Parse arguments """
    parser = worker.parseargs('Country/region enrichment')
    parser.add_argument('--country-region-url', dest='country_region_url',
                        default="https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json",
                        help="Country region URL in json format")

    return parser.parse_args()


def process(actapi, country_list):
    """Fetch ISO-3166 list, process and print generic_uploader
    data to stdout"""

    facts_added = {}

    for c_map in country_list:
        for location_type, location in c_map.items():
            if not location:
                continue  # Skip locations with empty values

            # Skip facts that are already added
            if location_type in LOCATION_TYPE_M and location not in facts_added:
                fact_type = LOCATION_TYPE_M[location_type]
                facts_added[location] = fact_type

                fact = actapi.fact(fact_type).source("location", location)

                if actapi.act_baseurl:
                    fact.add()  # Add fact to platform, if baseurl is specified
                else:
                    print(fact.json())  # Print fact to stdout, if baseurl is NOT specified


if __name__ == '__main__':
    ARGS = parseargs()

    actapi = act.Act(ARGS.act_baseurl, ARGS.user_id, ARGS.loglevel, ARGS.logfile, "country-region")
    country_list = worker.fetch_json(ARGS.country_region_url, ARGS.proxy_string, ARGS.timeout)

    process(actapi, country_list)
