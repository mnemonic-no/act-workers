#!/usr/bin/env python3

"""NiFi worker to pass Scio produced data to the ACT platform"""

import argparse
import json
import os
import sys
import traceback
from logging import error, warning
from typing import Callable, Dict, Set, Text, cast

import act.api
from act.api.helpers import handle_fact, handle_uri
from act.api.libs import cli

from act.workers.libs import worker

EXTRACT_GEONAMES = ["countries"]

EXTRACT_INDICATORS = ["md5", "sha1", "sha256", "fqdn", "uri", "ipv4net"]

EXTRACT_VULNERABILITIES = ["cve", "msid"]

SCIO_GEONAMES_ACT_MAP = {
    "countries": "country",
    "regions": "region",
    "regions-derived": "region",
    "sub-regions": "subRegion",
    "sub-regions-derived": "subRegion",
}

SCIO_INDICATOR_ACT_MAP = {
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "ipv4net": "ipv4Network",
    "cve": "vulnerability",
    "msid": "vulnerability",
}

ACT_FN_MAP: Dict[Text, Callable] = {"vulnerability": lambda x: x.lower()}


def parseargs() -> argparse.ArgumentParser:
    """Parse arguments"""
    parser = worker.parseargs("Get SCIO reports and IOCs from stdin")

    parser.add_argument(
        "--no-tlp-access-mode",
        action="store_true",
        help="Do not set access mode from TLP on document. If not set, facts will "
        + "have access-mode=Public for tlp=WHITE/GREEN otherwise access-mode=RoleBased",
    )

    parser.add_argument(
        "--no-organization-from-owner",
        action="store_true",
        help="Do not apply organization from owner",
    )

    return parser


def get_scio_report() -> Dict:
    """Read scio report from stdin"""

    return cast(Dict, json.load(sys.stdin))


def report_mentions_fact(
    actapi: act.api.Act,
    object_type: Text,
    object_values: Set[Text],
    report_id: Text,
    output_format: Text,
) -> None:
    """Add mentions fact to report"""
    for value in set(object_values):
        handle_fact(
            actapi.fact("mentions")
            .source("report", report_id)
            .destination(object_type, value),
            output_format,
        )


def add_indicators_to_act(
    actapi: act.api.Act, indicators: Dict, report_id: Text, output_format: Text
) -> None:
    """Create facts of indicators map"""

    # Loop over all items under indicators in report
    for scio_indicator_type in EXTRACT_INDICATORS:
        # Get object type from ACT (default to object type in SCIO)
        act_indicator_type = SCIO_INDICATOR_ACT_MAP.get(
            scio_indicator_type, scio_indicator_type
        )

        value_fn = ACT_FN_MAP.get(act_indicator_type, lambda x: x)

        values = {value_fn(value) for value in indicators.get(scio_indicator_type, [])}

        report_mentions_fact(
            actapi, act_indicator_type, values, report_id, output_format
        )

    # For IPv4+IPv6 addresses, create mention facts
    # Use ip_obj to return exploded, normalized IPv4 and IPv6 address
    for ip in set(indicators.get("ipv4", []) + indicators.get("ipv6", [])):
        try:
            handle_fact(
                actapi.fact("mentions")
                .source("report", report_id)
                .destination(*act.api.helpers.ip_obj(ip)),
                output_format,
            )
        except ValueError as err:
            warning(f"Creating fact to {ip} fails on IP validation {err}")

    # For SHA256, create content object
    for sha256 in set(indicators.get("sha256", [])):
        handle_fact(
            actapi.fact("represents")
            .source("hash", sha256)
            .destination("content", sha256),
            output_format,
        )

    # Add emails as URI components
    for email in set(indicators.get("email", [])):
        try:
            email_uri = f"email://{email}"
            handle_uri(actapi, email_uri, output_format=output_format)

            handle_fact(
                actapi.fact("mentions")
                .source("report", report_id)
                .destination("uri", email_uri),
                output_format,
            )
        except act.api.schema.MissingField:
            warning(f"Unable to create facts from uri: {email_uri}")

    # Add all URI components
    for uri in set(indicators.get("uri", [])):
        try:
            handle_uri(actapi, uri, output_format=output_format)
        except act.api.schema.MissingField:
            warning(f"Unable to create facts from uri: {uri}")


def add_locations_to_act(
    actapi: act.api.Act, locations_map: Dict, report_id: Text, output_format: Text
) -> None:
    """Create facts from locations map"""

    # Locations (countries, regions, sub regions)
    for location_type in EXTRACT_GEONAMES:
        locations = {x["name"] for x in locations_map.get(location_type, [])}

        report_mentions_fact(
            actapi,
            SCIO_GEONAMES_ACT_MAP[location_type],
            locations,
            report_id,
            output_format,
        )


def add_vulnerabilities_to_act(
    actapi: act.api.Act, vulnerabilities: Dict, report_id: Text, output_format: Text
) -> None:
    """Create facts from vulnerabilities map"""

    # Locations (countries, regions, sub regions)
    for vuln_type in EXTRACT_VULNERABILITIES:
        value_fn = ACT_FN_MAP.get("vulnerability", lambda x: x)

        values = {value_fn(value) for value in vulnerabilities.get(vuln_type, [])}

        report_mentions_fact(actapi, "vulnerability", values, report_id, output_format)


def add_to_act(actapi: act.api.Act, doc: Dict, output_format: Text = "json") -> None:
    """Add a report to the ACT platform"""

    report_id: Text = doc["hexdigest"]
    filename: Text = os.path.basename(doc.get("filename", "NN"))
    title: Text = doc.get("title", filename)

    indicators: Dict = doc.get("indicators", {})
    vulnerabilities: Dict = doc.get("vulnerabilities", {})
    locations: Dict = doc.get("locations", {})

    try:
        # Report title
        handle_fact(
            actapi.fact("name", title).source("report", report_id), output_format
        )
    except act.api.base.ResponseError as e:
        error("Unable to create fact: %s" % e)

    try:
        if doc.get("uri"):
            # URI reference
            handle_fact(
                actapi.fact("represents")
                .source("report", report_id)
                .destination("content", report_id),
                output_format,
            )
            # URI reference
            handle_fact(
                actapi.fact("at")
                .source("content", report_id)
                .destination("uri", doc["uri"]),
                output_format,
            )
    except act.api.base.ResponseError as e:
        error("Unable to create fact: %s" % e)

    add_indicators_to_act(actapi, indicators, report_id, output_format)
    add_vulnerabilities_to_act(actapi, vulnerabilities, report_id, output_format)
    add_locations_to_act(actapi, locations, report_id, output_format)

    # Threat actor
    report_mentions_fact(
        actapi,
        "threatActor",
        doc.get("threatactor", {}).get("ThreatActors", []),
        report_id,
        output_format,
    )

    # Tools
    report_mentions_fact(
        actapi,
        "tool",
        doc.get("tools", {}).get("Tools", []),
        report_id,
        output_format,
    )

    # Sector
    report_mentions_fact(
        actapi,
        "sector",
        set(doc.get("sectors", {}).get("sectors", [])),
        report_id,
        output_format,
    )

    # Tactic
    report_mentions_fact(
        actapi,
        "tactic",
        set(doc.get("mitre_attack", {}).get("Tactics", [])),
        report_id,
        output_format,
    )

    # Technique
    report_mentions_fact(
        actapi,
        "technique",
        set(doc.get("mitre_attack", {}).get("Techniques", [])),
        report_id,
        output_format,
    )

    # SubTechniques
    report_mentions_fact(
        actapi,
        "technique",
        set(doc.get("mitre_attack", {}).get("SubTechniques", [])),
        report_id,
        output_format,
    )


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/act.ini"
    # and ~/config/act/act.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    actapi = worker.init_act(args)

    doc = get_scio_report()

    if not args.no_tlp_access_mode:
        actapi.config.access_mode = (
            "Public" if doc.get("tlp") in ("GREEN", "WHITE") else "RoleBased"
        )

    if not args.no_organization_from_owner:
        owner = doc.get("owner")

        if owner:
            actapi.config.organization = owner

    # Add IOCs from reports to the ACT platform
    add_to_act(
        actapi,
        doc,
        args.output_format,
    )


def main_log_error() -> None:
    """Execute main() and log errors to error"""
    try:
        main()
    except Exception:
        error(f"Unhandled exception: {traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main_log_error()
