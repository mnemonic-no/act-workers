#!/usr/bin/env python3

"""url unshortener worker for the ACT platform

Copyright 2018 the ACT project <opensource@mnemonic.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""


import argparse
import re
import traceback
from logging import debug, error, warning
from typing import List, Set, Text, Tuple, Union

import act.api
import stix2
import urllib3
from act.api.libs import cli
from stix2 import parse
from stix2.v20.sro import Relationship

import act
from act.workers.libs import worker
from act.workers.libs.stix import (PatternNotSupported, expand_techniques,
                                   parse_single_stix_pattern)

StixObject = Union[
    stix2.v20.sdo.AttackPattern,
    stix2.v20.sdo.Campaign,
    stix2.v20.sdo.CourseOfAction,
    stix2.v20.sdo.Identity,
    stix2.v20.sdo.Indicator,
    stix2.v20.sdo.IntrusionSet,
    stix2.v20.sdo.Malware,
    stix2.v20.sdo.ObservedData,
    stix2.v20.sdo.Report,
    stix2.v20.sdo.ThreatActor,
    stix2.v20.sdo.Tool,
    stix2.v20.sdo.Vulnerability,
]


def parseargs() -> argparse.Namespace:
    parser = worker.parseargs("Unit42 Playbook worker")

    parser.add_argument(
        "--playbook-uri",
        default="https://github.com/pan-unit42/playbook_viewer/archive/master.zip",
        help="URI to zip dump of playbook repository. Supports URL and local files.",
    )

    return cli.handle_args(parser)


def resolve_triplets(
    playbook: stix2.v20.bundle.Bundle,
) -> List[Tuple[StixObject, Relationship, StixObject]]:
    objects = {
        obj.id: obj for obj in playbook.objects if not obj.type == "relationship"
    }

    triplets = []

    for obj in playbook.objects:
        if obj.type != "relationship":
            continue

        triplets.append((objects[obj.source_ref], obj, objects[obj.target_ref]))

    return triplets


def handle_indicator(
    api: act.api.Act,
    source: StixObject,
    relationship: Relationship,
    target: StixObject,
    output_format: Text,
) -> None:
    try:
        pattern_type, pattern_value = parse_single_stix_pattern(source.pattern)
    except PatternNotSupported:
        debug("Unsupported indicator pattern: %s", source.pattern)
        return

    types = (pattern_type, relationship.relationship_type, target.type)

    if types == ("url:value", "indicates", "campaign"):
        act.api.helpers.handle_uri(api, pattern_value, output_format=output_format)
        act.api.helpers.handle_fact(
            api.fact("observedIn")
            .source("uri", pattern_value)
            .destination("incident", target.id),
            output_format=output_format,
        )

    else:
        debug("Unsupported indicator types: %s", types)


def handle_campaign(
    api: act.api.Act, campaign: stix2.v20.sdo.Campaign, output_format: Text
) -> None:
    act.api.helpers.handle_fact(
        api.fact("name", campaign.name).source("incident", campaign.id),
        output_format=output_format,
    )


def handle_campaign_techniques(
    api: act.api.Act,
    campaign: stix2.v20.sdo.Campaign,
    techniques: Set[Text],
    output_format: Text,
) -> None:

    handle_campaign(api, campaign, output_format)

    for technique in techniques:
        act.api.helpers.handle_fact(
            api.fact("observedIn")
            .source("technique", technique)
            .destination("incident", campaign.id),
            output_format=output_format,
        )


def process(
    api: act.api.Act,
    playbook_uri: Text,
    proxy_string: Text,
    output_format: Text = "json",
) -> None:
    """Retrieve playbooks and handle objects"""

    for filename, file in worker.zip_files(playbook_uri, proxy_string):

        if re.search(r"/playbook_json/.*.json$", filename):
            playbook = parse(file, allow_custom=True)

            triplets = resolve_triplets(playbook)

            for source, rel, target in triplets:

                # Get source type, relationship type and target type
                types = (source.type, rel.relationship_type, target.type)

                # print(types)

                if types == ("course-of-action", "mitigates", "attack-pattern"):
                    pass
                elif types == ("campaign", "uses", "attack-pattern"):
                    handle_campaign_techniques(
                        api, source, expand_techniques(target), output_format
                    )
                elif types == ("campaign", "targets", "identity"):
                    pass
                elif types == ("report", "attributed-to", "intrusion-set"):
                    pass
                elif types == ("campaign", "attributed-to", "intrusion-set"):
                    pass

                elif source.type == "indicator":
                    handle_indicator(api, source, rel, target, output_format)
                else:
                    warning("Unsupported types: %s", types)


def main() -> None:
    """Main function"""
    # Look for default ini file in "/etc/act.ini" and
    # ~/config/act/act.ini (or replace .config with
    # $XDG_CONFIG_DIR if set)
    args = parseargs()

    actapi = worker.init_act(args)

    process(actapi, args.playbook_uri, args.proxy_string, args.output_format)


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
