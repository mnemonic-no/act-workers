#!/usr/bin/env python3

"""

Worker for Mitre ATT&CK, using the STIX implementation available here:

    https://github.com/mitre/cti

    ATT&CK Property     STIX Object type        ACT object
    =========================================================
    Technique           attack-pattern          technique
    Group               intrusion-set           threatActor
    Software	        malware or tool         tool
    Mitigation	        course-of-action        n/a

"""

import argparse
import os
import sys
import traceback
from logging import error, info, warning
from typing import Any, Dict, List, Text

import stix2
from stix2 import Filter, MemoryStore, parse

import act.api
from act.api.helpers import handle_fact
from act.workers.libs import worker

MITRE_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "pre": "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
}

DEFAULT_NOTIFY_CACHE = os.path.join(os.environ["HOME"], "act-mitre-attack-notify.cache")


class NotificationError(Exception):
    """NotificationError"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Mitre ATT&CK worker')
    parser.add_argument('--smtphost', dest='smtphost', help="SMTP host used to send revoked/deprecated objects")
    parser.add_argument('--sender', dest='sender', help="Sender address used to send revoked/deprecated objects")
    parser.add_argument('--recipient', dest='recipient', help="Recipient address used to send revoked/deprecated objects")
    parser.add_argument(
        '--type',
        choices=list(MITRE_URLS.keys()),
        help='Specify a single type to download (enterprise, mobile or pre). Default is to fetch all')
    parser.add_argument('--notifycache', dest='notifycache', help="Cache for revoked/deprecated objects", default=DEFAULT_NOTIFY_CACHE)

    return parser


def get_attack(url: str, proxy_string: str, timeout: int) -> MemoryStore:
    """Fetch Mitre ATT&CK JSON data in Stix2 format and return a Stix2 memory store"""
    attack = worker.fetch_json(url, proxy_string, timeout)

    # Create memory store
    mem = MemoryStore()

    # Add all objects to the memory store
    for obj in parse(attack, allow_custom=True).objects:
        mem.add(obj)

    return mem


def add_techniques(client, attack: MemoryStore, output_format: Text = "json") -> List[stix2.AttackPattern]:
    """
        extract objects/facts related to ATT&CK techniques

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []

    # ATT&CK concept    STIX Object type        ACT object
    # =========================================================
    # Technique         attack-pattern          technique
    # Filter out ATT&CK techniques (attack-pattern) from bundle

    for technique in attack.query([Filter("type", "=", "attack-pattern")]):
        if getattr(technique, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(technique)
            continue

        if getattr(technique, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(technique)

        # Mitre ATT&CK Tactics are implemented in STIX as kill chain phases with kill_chain_name "mitre-attack"
        for tactic in technique.kill_chain_phases:
            if tactic.kill_chain_name != "mitre-attack":
                continue

            handle_fact(
                client.fact("accomplishes")
                .source("technique", technique.name)
                .destination("tactic", tactic.phase_name),
                output_format=output_format
            )

    return notify


def add_groups(client, attack: MemoryStore, output_format: Text = "json") -> List[stix2.AttackPattern]:
    """
        extract objects/facts related to ATT&CK Groups

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []

    # ATT&CK concept    STIX Object type        ACT object
    # =========================================================
    # Group	        intrusion-set           threatActor
    #
    # Filter out ATT&CK groups (intrusion-set) from bundle

    for group in attack.query([Filter("type", "=", "intrusion-set")]):
        if getattr(group, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(group)
            continue

        if getattr(group, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(group)

        for alias in getattr(group, "aliases", []):
            if group.name != alias:
                handle_fact(
                    client.fact("alias")
                    .bidirectional("threatActor", group.name, "threatActor", alias),
                    output_format=output_format
                )

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Software         relationship where relationship_type == "uses",
        #                    points to a target object with type== "malware" or "tool"

        for tool in attack.related_to(group, relationship_type="uses"):
            if tool.type not in ("malware", "tool"):
                continue

            chain = act.api.fact.fact_chain(
                client.fact("classifiedAs")
                .source("content", "*")
                .destination("tool", tool.name.lower()),
                client.fact("observedIn", "event")
                .source("content", "*")
                .destination("event", "*"),
                client.fact("attributedTo", "incident")
                .source("event", "*")
                .destination("incident", "*"),
                client.fact("attributedTo", "threatActor")
                .source("incident", "*")
                .destination("threatActor", group.name)
            )

            for fact in chain:
                handle_fact(fact, output_format=output_format)

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Technqiues       relationship where relationship_type == "uses", points to
        #                    a target object with type == "attack-pattern"

        for technique in attack.related_to(group, relationship_type="uses"):
            if technique.type != "attack-pattern":
                continue

            chain = act.api.fact.fact_chain(
                client.fact("classifiedAs", "technique")
                .source("event", "*")
                .destination("technique", technique.name),
                client.fact("attributedTo", "incident")
                .source("event", "*")
                .destination("incident", "*"),
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", group.name)
            )

            for fact in chain:
                handle_fact(fact, output_format=output_format)

    return notify


def add_software(client, attack: MemoryStore, output_format: Text = "json") -> List[stix2.AttackPattern]:
    """
        extract objects/facts related to ATT&CK Software
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []

    for software in attack.query([Filter("type", "in", ["tool", "malware"])]):
        tool_name = software.name.lower()

        # Tool category
        handle_fact(
            client.fact("category", software.type).source("tool", tool_name),
            output_format=output_format
        )

        if getattr(software, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(software)
            continue

        if getattr(software, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(software)

        for alias in getattr(software, "x_mitre_aliases", []):
            if tool_name != alias.lower():
                # Tool category (alias)
                handle_fact(
                    client.fact("category", software.type).source("tool", alias.lower()),
                    output_format=output_format
                )
                handle_fact(
                    client.fact("alias")
                    .bidirectional("tool", tool_name, "tool", alias.lower()),
                    output_format=output_format
                )

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Technqiues       relationship where relationship_type == "uses", points to
        #                    a target object with type == "attack-pattern"

        for technique in attack.related_to(software, relationship_type="uses"):
            if technique.type != "attack-pattern":
                continue

            handle_fact(
                client.fact("implements")
                .source("tool", software.name.lower())
                .destination("technique", technique.name),
                output_format=output_format
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
        warning("Cache file {} not found, will be created if necessary".format(filename))

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
        notify: List[stix2.AttackPattern],
        smtphost: str,
        sender: str,
        recipient: str,
        url: str) -> List[str]:
    """
    Process revoked objects

    Args:
        notify(attack[]):   Array of revoked/deprecated Stix objects
        notifycache(str):   Filename of notify cache
        smtphost(str):      SMTP host used to notify of revoked/deprecated objects
        sender(str):        sender address used to notify of revoked/deprecated objects
        recipient(str):     recipient address used to notify of revoked/deprecated objects

    smtphost, sender AND recipient must be set to notify of revoked/deprecated objects

    Return list of IDs that was successfully notified

    """

    notified = []

    if not (smtphost and recipient and sender):
        error("--smtphost, --recipient and --sender must be set to send revoked/deprecated objects on email")
        return []

    body = url + "\n\n"
    warning("[{}]".format(url))

    for obj in notify:
        if getattr(obj, "revoked", None):
            text = "revoked: {}:{}".format(obj.type, obj.name)

        elif getattr(obj, "x_mitre_deprecated", None):
            text = "deprecated: {}:{}".format(obj.type, obj.name)

        else:
            raise NotificationError("object tis not deprecated or revoked: {}:{}".format(obj.type, obj.name))

        notified.append(obj.id)

        body += text + "\n"
        warning(text)

    worker.sendmail(smtphost, sender, recipient, "Revoked/deprecated objects from MITRE/ATT&CK", body)
    info("Email sent to {}".format(recipient))

    return notified


def main() -> None:
    """ Main function """

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if args.type:
        types = [args.type]
    else:
        types = list(MITRE_URLS.keys())

    for mitre_type in types:
        url = MITRE_URLS.get(mitre_type.lower())

        if not url:
            error("Unknown mitre type: {}. Valid types: {}".format(mitre_type, ",".join(MITRE_URLS.keys())))
            sys.exit(2)

        cache = notify_cache(args.notifycache)

        # Get attack dataset as Stix Memory Store
        attack = get_attack(url, args.proxy_string, args.http_timeout)

        techniques_notify = add_techniques(actapi, attack, args.output_format)
        groups_notify = add_groups(actapi, attack, args.output_format)
        software_notify = add_software(actapi, attack, args.output_format)

        # filter revoked objects from those allready notified
        notify = [
            notify
            for notify in techniques_notify + groups_notify + software_notify
            if notify.id not in cache
        ]

        if notify:
            notified = send_notification(notify, args.smtphost, args.sender, args.recipient, url)

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


if __name__ == '__main__':
    main_log_error()
