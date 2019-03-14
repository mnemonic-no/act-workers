#!/usr/bin/env python3

"""NiFi worker to pass Scio produced data to the ACT platform"""

import argparse
import json
import sys
import traceback
from logging import error

import act
from act.helpers import handle_fact, handle_uri

EXTRACT_GEONAMES = ["countries", "regions", "regions-derived",
                    "sub-regions", "sub-regions-derived"]


EXTRACT_INDICATORS = ["md5", "sha1", "sha256",
                      "fqdn", "ipv4", "ipv6", "email",
                      "msid", "cve", "uri", "ipv4net"]

SCIO_GEONAMES_ACT_MAP = {
    "countries": "country",
    "regions": "region",
    "regions-derived": "region",
    "sub-regions": "subRegion",
    "sub-regions-derived": "subRegion"
}

SCIO_INDICATOR_ACT_MAP = {
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "ipv4net": "ipv4Network",
    "cve": "vulnerability",
    "msid": "vulnerability",
}


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='Get SCIO reports and IOCs from stdin')
    parser.add_argument('--userid', dest='act_user_id', required=True, help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True, help='API URI')
    parser.add_argument("--logfile", dest="logfile", help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")

    return parser.parse_args()


def get_scio_report():
    """Read scio report from stdin"""

    return json.load(sys.stdin)


def report_mentions_fact(actapi, object_type, object_values, report_id):
    for value in list(set(object_values)):
        try:
            handle_fact(
                actapi.fact("mentions", object_type)
                .source("report", report_id)
                .destination(object_type, value)
            )
        except act.base.ResponseError as e:
            error("Unable to create linked fact: %s" % e)


def add_to_act(actapi, doc):
    """Add a report to the ACT platform"""

    report_id = doc["hexdigest"]

    title = doc.get("title", "No title")

    try:
        # Report title
        handle_fact(
            actapi.fact("name", title)
            .source("report", report_id)
        )
    except act.base.ResponseError as e:
        error("Unable to create fact: %s" % e)

    indicators = doc.get("indicators", {})

    # Loop over all items under indicators in report
    for scio_indicator_type in EXTRACT_INDICATORS:
        # Get object type from ACT (default to object type in SCIO)
        act_indicator_type = SCIO_INDICATOR_ACT_MAP.get(scio_indicator_type,
                                                        scio_indicator_type)
        report_mentions_fact(
            actapi,
            act_indicator_type,
            indicators.get(scio_indicator_type, []),
            report_id)

    # For SHA256, create content object
    for sha256 in list(set(indicators.get("sha256", []))):
        handle_fact(
            actapi.fact("represents")
            .source("hash", sha256)
            .destination("content", sha256))

    # Add all URI components
    for uri in list(set(indicators.get("uri", []))):
        handle_uri(actapi, uri)

    # Locations (countries, regions, sub regions)
    for location_type in EXTRACT_GEONAMES:
        locations = doc.get("geonames", {}).get(location_type, [])

        report_mentions_fact(
            actapi,
            SCIO_GEONAMES_ACT_MAP[location_type],
            locations,
            report_id)

    # Threat actor
    report_mentions_fact(
        actapi,
        "threatActor",
        doc.get("threat-actor", {}).get("names", []),
        report_id)

    # Tools
    report_mentions_fact(
        actapi,
        "tool",
        [tool.lower() for tool in doc.get("tools", {}).get("names", [])],
        report_id)

    # Sector
    report_mentions_fact(
        actapi,
        "sector",
        doc.get("sectors", []),
        report_id)


if __name__ == '__main__':
    ARGS = parseargs()

    try:
        # Add IOCs from reports to the ACT platform
        add_to_act(
            act.Act(ARGS.act_baseurl, ARGS.act_user_id, ARGS.loglevel, ARGS.logfile, "scio"),
            get_scio_report()
        )
    except Exception as e:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise
