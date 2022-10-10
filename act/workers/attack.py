#!/usr/bin/env python3

""" Worker for Mitre ATT&CK """

import argparse
import os
import sys
import traceback
from collections import defaultdict
from logging import error, info, warning
from typing import Any, Dict, List, Optional, Text, Union

import act.api
import attampck.data
from act.api.helpers import Act, handle_fact, handle_facts
from act.api.libs import cli
from attampck import matrices, stixmap
from attampck.data import resolve_mitre_id
from stix2 import (AttackPattern, Filter, IntrusionSet, Malware, Relationship,
                   Tool)

from act.workers.libs import worker

Software = Union[Tool, Malware]
Attack = Union[Software, AttackPattern, IntrusionSet, Malware, Tool]


MITRE_TYPES = [
    matrices.ENTERPRISE,
    matrices.ICS,
    matrices.MOBILE,
]


DEFAULT_NOTIFY_CACHE = os.path.join(os.environ["HOME"], "act-mitre-attack-notify.cache")


class NotificationError(Exception):
    pass


def parseargs() -> argparse.ArgumentParser:
    """Parse arguments"""
    parser = worker.parseargs("Mitre ATT&CK worker")
    parser.add_argument(
        "--smtphost",
        dest="smtphost",
        help="SMTP host used to send revoked/deprecated objects",
    )
    parser.add_argument(
        "--sender",
        dest="sender",
        help="Sender address used to send revoked/deprecated objects",
    )
    parser.add_argument(
        "--recipient",
        dest="recipient",
        help="Recipient address used to send revoked/deprecated objects",
    )
    parser.add_argument(
        "--type",
        choices=list(MITRE_TYPES),
        help="Specify a single type to download. Default is to fetch all",
    )
    parser.add_argument(
        "--notifycache",
        dest="notifycache",
        help="Cache for revoked/deprecated objects",
        default=DEFAULT_NOTIFY_CACHE,
    )

    return parser


def deprecated_or_revoked(obj: Any) -> Optional[bool]:
    """
    Return true if object has a truthy "revoked" or "deprecated" attribute,
    otherwise False
    """
    return getattr(obj, "revoked", None) or getattr(obj, "deprecated", None)


def handle_techniques(
    client: Act,
    technique: AttackPattern,
    main_technique: Optional[AttackPattern],
    tactic_id_map: Dict[Text, Text],
    output_format: Text = "json",
) -> List[AttackPattern]:

    """
    Args:
    client:                Act Client
    technique (str):       Technique or subtechnique ID
    main_technique (str):  If set, technique is a sub technique
    output_format (str):   Fact output if sent to stdout (text | json)
    """

    technique_id = resolve_mitre_id(technique)

    if deprecated_or_revoked(technique):
        # Object is revoked/deprecated, add to notification list but do not add to facts that should be added to the platform
        return [technique]

    if main_technique:
        handle_fact(
            client.fact("subTechniqueOf")
            .source("technique", technique_id)
            .destination("technique", resolve_mitre_id(main_technique)),
            output_format=output_format,
        )

    handle_fact(
        client.fact("name", technique.name).source("technique", technique_id),
        output_format=output_format,
    )

    # Mitre ATT&CK Tactics are implemented in STIX as kill chain phases with kill_chain_name "mitre-attack"
    for phase in technique.kill_chain_phases:

        if phase.kill_chain_name != "mitre-attack":
            continue

        tactic_id = tactic_id_map[phase.phase_name]

        handle_fact(
            client.fact("accomplishes")
            .source("technique", technique_id)
            .destination("tactic", tactic_id),
            output_format=output_format,
        )

    return []


def add_tactics(
    client: Act,
    attack: attampck.data.Attampck,
    matrix: matrices,
    output_format: Text = "json",
) -> Dict[Text, Text]:
    """
        extract objects/facts related to ATT&CK tactics and return map of shortname -> id for tactics

    Args:
        attack (matrices):       Attack matrice
        output_format (Text):    "json" or "str" output format

    """

    shortname_id_map: Dict[Text, Text] = {}

    for tactic in attack.iterate(matrix, stixmap.TACTIC):
        tactic_id = resolve_mitre_id(tactic)

        shortname_id_map[tactic.x_mitre_shortname] = tactic_id

        handle_fact(
            client.fact("name", tactic.name).source("tactic", tactic_id),
            output_format=output_format,
        )

    return shortname_id_map


def add_techniques(
    client: Act,
    attack: attampck.data.Attampck,
    matrix: matrices,
    tactic_id_map: Dict[Text, Text],
    output_format: Text = "json",
) -> List[AttackPattern]:
    """
        extract objects/facts related to ATT&CK techniques

    Args:
        attack (matrices):       Attack matrice
        output_format (Text):    "json" or "str" output format

    """

    notify = []

    for technique in attack.iterate(matrix, stixmap.TECHNIQUE):

        # Subtechniques are added below
        if getattr(technique, "x_mitre_is_subtechnique", False):
            continue

        notify += handle_techniques(
            client, technique, None, tactic_id_map, output_format
        )

        for subtechnique in attack.get_subtechniques(technique.id):
            notify += handle_techniques(
                client, subtechnique, technique, tactic_id_map, output_format
            )

    return notify


def add_groups(
    client: Act,
    attack: attampck.data.Attampck,
    matrix: matrices,
    uses: Dict[Text, List[Relationship]],
    output_format: Text = "json",
) -> List[IntrusionSet]:
    """
        extract objects/facts related to ATT&CK Threat Actors

    Args:
        attack (matrices):       Attack matrice
        output_format (Text):    "json" or "str" output format

    """

    notify: List[IntrusionSet] = []

    # ICS does not have actors
    for actor in attack.iterate(matrix, stixmap.GROUP):

        if deprecated_or_revoked(actor):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(actor)
            continue

        for alias in actor.aliases:
            if actor.name != alias:
                handle_fact(
                    client.fact("alias").bidirectional(
                        "threatActor",
                        actor.name,
                        "threatActor",
                        alias,
                    ),
                    output_format=output_format,
                )

        for target in uses.get(actor.id, []):

            if target.type in ("malware", "tool"):
                tool_name = target.name.strip()

                if not tool_name:
                    # Skip empty tools found in ATT&CK
                    continue

                handle_facts(
                    act.api.fact.fact_chain(
                        client.fact("classifiedAs")
                        .source("content", "*")
                        .destination("tool", tool_name),
                        client.fact("observedIn")
                        .source("content", "*")
                        .destination("incident", "*"),
                        client.fact("attributedTo")
                        .source("incident", "*")
                        .destination("threatActor", actor.name),
                    ),
                    output_format=output_format,
                )

            elif target.type == "attack-pattern":
                handle_facts(
                    act.api.fact.fact_chain(
                        client.fact("observedIn")
                        .source("technique", resolve_mitre_id(target))
                        .destination("incident", "*"),
                        client.fact("attributedTo")
                        .source("incident", "*")
                        .destination("threatActor", actor.name),
                    ),
                    output_format=output_format,
                )

    return notify


def add_software(
    client: Act,
    attack: attampck.data.Attampck,
    matrix: matrices,
    uses: Dict[Text, List[Relationship]],
    output_format: Text = "json",
) -> List[Software]:
    """
        extract objects/facts related to ATT&CK Software
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args: attack (matrices):       Attack matrice
        output_format (Text):    "json" or "str" output format

    """

    notify: List[Software] = []

    for stix_type in (stixmap.TOOL, stixmap.MALWARE):
        # Enterprise matrix has malwares and tools, but preattack has none of them
        for software in attack.iterate(matrix, stix_type):

            if deprecated_or_revoked(software):
                # Object is revoked/deprecated, add to notification list but do not add to facts that should be added to the platform
                notify.append(software)
                continue

            tool_name = software.name

            # Tool category
            handle_fact(
                client.fact("category", software.type).source("tool", tool_name),
                output_format=output_format,
            )

            for alias in getattr(software, "x_mitre_aliases", []):
                alias_name = alias

                if tool_name != alias_name:
                    # Tool category (alias)
                    handle_fact(
                        client.fact("category", software.type).source(
                            "tool", alias_name
                        ),
                        output_format=output_format,
                    )
                    handle_fact(
                        client.fact("alias").bidirectional(
                            "tool", tool_name, "tool", alias_name
                        ),
                        output_format=output_format,
                    )

            for target in uses.get(software.id, []):
                if target.type != "attack-pattern":
                    continue

                handle_fact(
                    client.fact("implements")
                    .source("tool", software.name)
                    .destination("technique", resolve_mitre_id(target)),
                    output_format=output_format,
                )

    return notify


def notify_cache(filename: str) -> Dict[Text, bool]:
    """
    Read notify cache from filename
    Args:
        filename(str):      Cache filename

    """

    cache = {}

    try:
        with open(filename) as f:
            for line in f:
                if line:
                    cache[line.strip()] = True
    except FileNotFoundError:
        warning("Cache file %s not found, will be created if necessary", filename)

    return cache


def add_to_cache(filename: str, entry: str) -> None:
    """
    Add entry to cache

    Args:
        filename(str):      Cache filename
        entry(str):         Cache entry
    """

    with open(filename, "a") as f:
        f.write(entry.strip())
        f.write("\n")


def send_notification(
    notify: List[Attack],
    smtphost: Text,
    sender: Text,
    recipient: Text,
    matrix: Text,
) -> List[Text]:
    """
    Process revoked objects

    Args:
        notify(attack[]):   Array of revoked/deprecated objects
        notifycache(str):   Filename of notify cache
        smtphost(str):      SMTP host used to notify of revoked/deprecated objects
        sender(str):        sender address used to notify of revoked/deprecated objects
        recipient(str):     recipient address used to notify of revoked/deprecated objects

    smtphost, sender AND recipient must be set to notify of revoked/deprecated objects

    Return list of IDs that was successfully notified

    """

    notified = []

    if not (smtphost and recipient and sender):
        error(
            "--smtphost, --recipient and --sender must be set to send revoked/deprecated objects on email"
        )
        return []

    body = matrix + "\n\n"
    warning("[%s]", matrix)

    for obj in notify:
        obj_description = f"{obj.id}:{resolve_mitre_id(obj)}:{obj.name}"
        if getattr(obj, "revoked", None):
            text = f"revoked: {obj_description}"

        elif getattr(obj, "deprecated", None):
            text = f"deprecated: {obj_description}"

        else:
            raise NotificationError(
                f"object is not deprecated or revoked: {obj.id}:{obj.name}"
            )

        notified.append(obj.id)

        body += text + "\n"
        warning(text)

    worker.sendmail(
        smtphost,
        sender,
        recipient,
        "Revoked/deprecated objects from MITRE/ATT&CK",
        body,
    )
    info("Email sent to %s", recipient)

    return notified


def main() -> None:
    """Main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    actapi = worker.init_act(args)

    proxies = (
        {"http": args.proxy_string, "https": args.proxy_string}
        if args.proxy_string
        else None
    )

    attack = attampck.data.Attampck(proxies=proxies)

    types = (
        [getattr(attampck.matrices, args.type.upper())] if args.type else MITRE_TYPES
    )

    for matrix in types:
        if not matrix:
            error(
                "Unknown mitre type: %s. Valid types: %s",
                matrix,
                ",".join(attampck.matrices),
            )
            sys.exit(2)

        cache = notify_cache(args.notifycache)

        uses = defaultdict(list)

        for rel in attack.get_stix2_memorystore(matrix).query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "uses"),
            ]
        ):
            uses[rel.source_ref].append(attack.get(rel.target_ref))

        tactic_id_map = add_tactics(actapi, attack, matrix, args.output_format)
        techniques_notify = add_techniques(
            actapi, attack, matrix, tactic_id_map, args.output_format
        )

        groups_notify = add_groups(actapi, attack, matrix, uses, args.output_format)
        software_notify = add_software(actapi, attack, matrix, uses, args.output_format)

        # filter revoked objects from those allready notified
        notify: Attack = [
            notify
            for notify in techniques_notify + groups_notify + software_notify
            if notify.id not in cache
        ]

        if notify:
            notified = send_notification(
                notify,
                args.smtphost,
                args.sender,
                args.recipient,
                matrix,
            )

            for object_id in notified:
                # Add object to cache, so we will not be notified on the same object on the next run
                add_to_cache(args.notifycache, object_id)


def main_log_error() -> None:
    "Call main() and log all excetions  as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: %s", traceback.format_exc())
        raise


if __name__ == "__main__":
    main_log_error()
