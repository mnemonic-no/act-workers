#!/usr/bin/env python3

""" Worker for Mitre ATT&CK """

import argparse
import os
import sys
import traceback
from logging import error, info, warning
from typing import Dict, List, Optional, Text, Union

import act.api
from act.api.helpers import Act, handle_fact, handle_facts
from act.api.libs import cli
from pyattck import Attck

from act.workers.libs import worker

# This is only for typing
# We can not import these matrices, because then they be loaded
# by pyattack and it fails if you need proxy
AttckMatrice = Union["Enterprise", "ICS", "MobileAttck"]

MITRE_TYPES = ["enterprise", "ics", "mobile"]

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
        help="Specify a single type to download (enterprise, mobile or pre). Default is to fetch all",
    )
    parser.add_argument(
        "--notifycache",
        dest="notifycache",
        help="Cache for revoked/deprecated objects",
        default=DEFAULT_NOTIFY_CACHE,
    )

    return parser


def deprecated_or_revoked(obj):
    """
    Return true if object has a truthy "revoked" or "deprecated" attribute,
    otherwise False
    """
    return getattr(obj, "revoked", None) or getattr(obj, "deprecated", None)


def handle_techniques(
    client: Act,
    technique: "AttckTechnique",
    main_technique: Optional["AttckTechnique"],
    output_format: Text = "json",
) -> List:

    """
    Args:
    client:                Act Client
    technique (str):       Technique or subtechnique ID
    main_technique (str):  If set, technique is a sub technique
    output_format (str):   Fact output if sent to stdout (text | json)
    """

    if deprecated_or_revoked(technique):
        # Object is revoked/deprecated, add to notification list but do not add to facts that should be added to the platform
        return [technique]

    if main_technique:
        handle_fact(
            client.fact("subTechniqueOf")
            .source("technique", technique.id)
            .destination("technique", main_technique.id),
            output_format=output_format,
        )

    handle_fact(
        client.fact("name", technique.name).source("technique", technique.id),
        output_format=output_format,
    )

    # Mitre ATT&CK Tactics are implemented in STIX as kill chain phases with kill_chain_name "mitre-attack"
    for tactic in technique.tactics:
        handle_fact(
            client.fact("accomplishes")
            .source("technique", technique.id)
            .destination("tactic", tactic.id),
            output_format=output_format,
        )

        handle_fact(
            client.fact("name", tactic.name).source("tactic", tactic.id),
            output_format=output_format,
        )

    return []


def add_techniques(
    client: Act, matrice: AttckMatrice, output_format: Text = "json"
) -> List:
    """
        extract objects/facts related to ATT&CK techniques

    Args:
        attack (AttckMatrice):       Attack matrice
        output_format (Text):        "json" or "str" output format

    """

    notify = []

    for technique in matrice.techniques:
        notify += handle_techniques(client, technique, None, output_format)

        for subtechnique in getattr(technique, "subtechniques", []):
            # Pre Attack does not have sub techniques
            notify += handle_techniques(client, subtechnique, technique, output_format)

    return notify


def add_groups(
    client: Act, matrice: AttckMatrice, output_format: Text = "json"
) -> List:
    """
        extract objects/facts related to ATT&CK Threat Actors

    Args:
        attack (AttckMatrice):       Attack matrice
        output_format (Text):        "json" or "str" output format

    """

    notify: List = []

    # ICS does not have actors
    for actor in getattr(matrice, "actors", []):
        if deprecated_or_revoked(actor):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(actor)
            continue

        for alias in actor.alias:
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

        for tool in actor.known_tools:

            if not tool.strip():
                # Skip empty tools found in ATT&CK
                continue

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
                    .destination("threatActor", actor.name),
                ),
                output_format=output_format,
            )

        for technique in actor.techniques:
            handle_facts(
                act.api.fact.fact_chain(
                    client.fact("observedIn")
                    .source("technique", technique.id)
                    .destination("incident", "*"),
                    client.fact("attributedTo")
                    .source("incident", "*")
                    .destination("threatActor", actor.name),
                ),
                output_format=output_format,
            )

    return notify


def add_software(
    client: Act, matrice: AttckMatrice, output_format: Text = "json"
) -> List:
    """
        extract objects/facts related to ATT&CK Software
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        attack (AttckMatrice):       Attack matrice
        output_format (Text):        "json" or "str" output format

    """

    notify: List = []

    # Enterprise matrice has malwares and tools, but preattack has none of them
    for software in getattr(matrice, "malwares", []) + getattr(matrice, "tools", []):
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

        for alias in software.alias:
            alias_name = alias

            if tool_name != alias_name:
                # Tool category (alias)
                handle_fact(
                    client.fact("category", software.type).source("tool", alias_name),
                    output_format=output_format,
                )
                handle_fact(
                    client.fact("alias").bidirectional(
                        "tool", tool_name, "tool", alias_name
                    ),
                    output_format=output_format,
                )

        for technique in software.techniques:
            handle_fact(
                client.fact("implements")
                .source("tool", software.name)
                .destination("technique", technique.id),
                output_format=output_format,
            )

    return notify


def notify_cache(filename: str) -> Dict:
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
        warning(
            "Cache file {} not found, will be created if necessary".format(filename)
        )

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
    notify: List,
    smtphost: Text,
    sender: Text,
    recipient: Text,
    model: Text,
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

    body = model + "\n\n"
    warning("[{}]".format(model))

    for obj in notify:
        if getattr(obj, "revoked", None):
            text = "revoked: {}:{}".format(obj.id, obj.name)

        elif getattr(obj, "deprecated", None):
            text = "deprecated: {}:{}".format(obj.id, obj.name)

        else:
            raise NotificationError(
                "object is not deprecated or revoked: {}:{}".format(obj.id, obj.name)
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
    info("Email sent to {}".format(recipient))

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

    attack = Attck(proxies=proxies)

    types = [args.type] if args.type else MITRE_TYPES

    for mitre_type in types:
        if mitre_type not in MITRE_TYPES:
            error(
                "Unknown mitre type: {}. Valid types: {}".format(
                    mitre_type, ",".join(MITRE_TYPES)
                )
            )
            sys.exit(2)

        cache = notify_cache(args.notifycache)

        model = getattr(attack, mitre_type)

        techniques_notify = add_techniques(actapi, model, args.output_format)
        groups_notify = add_groups(actapi, model, args.output_format)
        software_notify = add_software(actapi, model, args.output_format)

        # filter revoked objects from those allready notified
        notify = [
            notify
            for notify in techniques_notify + groups_notify + software_notify
            if notify.id not in cache
        ]

        if notify:
            notified = send_notification(
                notify, args.smtphost, args.sender, args.recipient, mitre_type
            )

            for object_id in notified:
                # Add object to cache, so we will not be notified on the same object on the next run
                add_to_cache(args.notifycache, object_id)


def main_log_error() -> None:
    "Call main() and log all excetions  as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
