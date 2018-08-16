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

import os
from logging import error, warning, info
import act
from stix2 import parse, Filter, MemoryStore
import worker

MITRE_ENTERPRISE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_PRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
MITRE_MOBILE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
DEFAULT_NOTIFY_CACHE = os.path.join(os.environ["HOME"], "act-mitre-attack-notify.cache")


def parseargs():
    """ Parse arguments """
    parser = worker.parseargs('Mitre ATT&CK worker')
    parser.add_argument('--smtphost', dest='smtphost', help="SMTP host used to send revoked/deprecated objects")
    parser.add_argument('--sender', dest='sender', help="Sender address used to send revoked/deprecated objects")
    parser.add_argument('--recipient', dest='recipient', help="Recipient address used to send revoked/deprecated objects")
    parser.add_argument('--notifycache', dest='notifycache', help="Cache for revoked/deprecated objects", default=DEFAULT_NOTIFY_CACHE)
    args = parser.parse_args()

    return args


def get_attack(url, proxy_string, timeout):
    """Fetch Mitre ATT&CK JSON data in Stix2 format and return a Stix2 memory store"""
    attack = worker.fetch_json(url, proxy_string, timeout)

    # Create memory store
    mem = MemoryStore()

    # Add all objects to the memory store
    for obj in parse(attack, allow_custom=True).objects:
        mem.add(obj)

    return mem


def add_fact(client, source_type, source_values, fact_type, destination_type, destination_values, link_type="linked"):
    """
    Add facts for all combinations of source_values and destination_values,
    using the specified source_type, fact_type, destination_type and
    link_type.

    Args:
        client(act.Act):            ACT instance
        source_type(str):           ACT object source type
        source_values(str[]):       List of source values
        destination_type(str):      ACT object destination type
        destination_values(str[]):  List of destination values
        link_type(str):             linked|bidirectional

    link_type == linked, means a fact with a specified source and destination.
    link_type == bidirectional, means a fact where source/destination have a two way direction

    """

    # Ensure source/destination values lists, if not enclose in a list with a single value
    if isinstance(destination_values, str):
        destination_values = [destination_values]

    if isinstance(source_values, str):
        source_values = [source_values]

    for source_value in source_values:
        try:
            for destination_value in destination_values:
                fact = None
                if source_type == destination_type and source_value == destination_value:
                    continue  # Do not link to itself

                if link_type == "linked":
                    fact = client.fact(fact_type)\
                        .source(source_type, source_value)\
                        .destination(destination_type, destination_value)
                elif link_type == "bidirectional":
                    fact = client.fact(fact_type)\
                        .bidirectional(source_type, source_value)\
                        .bidirectional(destination_type, destination_value)
                else:
                    error("Illegal link_type: %s" % link_type)
                    continue

                if client.act_baseurl:  # Add fact toplatform
                    fact.add()
                else:
                    print(fact.json())  # Print fact to stdout, if baseurl is NOT set

        except act.base.ResponseError as e:
            error(e)
            continue


def get_techniques(attack):
    """
        extract objects/facts related to ATT&CK techniques

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []
    facts = []

    # ATT&CK concept    STIX Object type        ACT object
    # =========================================================
    # Technique         attack-pattern          technique
    # Filter out ATT&CK techniques (attack-pattern) from bundle

    for technique in attack.query(Filter("type", "=", "attack-pattern")):
        if getattr(technique, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(technique)
            continue

        if getattr(technique, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(technique)

        # Mitre ATT&CK Tactics are implemented in STIX as kill chain phases with kill_chain_name "mitre-attack"
        tactics = [
            tactic.phase_name
            for tactic in technique.kill_chain_phases
            if tactic.kill_chain_name == "mitre-attack"
        ]

        facts.append(("tactic", tactics, "usesTechnique", "technique", technique.name, "linked"))

    return (facts, notify)


def get_groups(attack):
    """
        extract objects/facts related to ATT&CK Groups

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []
    facts = []

    # ATT&CK concept    STIX Object type        ACT object
    # =========================================================
    # Group	        intrusion-set           threatActor
    #
    # Filter out ATT&CK groups (intrusion-set) from bundle

    for group in attack.query(Filter("type", "=", "intrusion-set")):
        if getattr(group, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(group)
            continue

        if getattr(group, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(group)

        if getattr(group, "aliases", None):
            facts.append(("threatActor",
                          group.name,
                          "threatActorAlias",
                          "threatActor",
                          group.aliases,
                          "bidirectional"))

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Software         relationship where relationship_type == "uses",
        #                    points to a target object with type== "malware" or "tool"

        uses_tools = [
            tool.name.lower()
            for tool in attack.related_to(group, relationship_type="uses")
            if tool.type in ("malware", "tool")
        ]

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Technqiues       relationship where relationship_type == "uses", points to
        #                    a target object with type == "attack-pattern"

        uses_techniques = [
            tech.name
            for tech in attack.related_to(group, relationship_type="uses")
            if tech.type in ("attack-pattern")
        ]

        facts.append(("threatActor", group.name, "usesTechnique", "technique", uses_techniques, "linked"))
        facts.append(("threatActor", group.name, "usesTool", "tool", uses_tools, "linked"))

    return (facts, notify)


def get_software(attack):
    """
        extract objects/facts related to ATT&CK Software
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []
    facts = []

    for software in attack.query(Filter("type", "in", ["tool", "malware"])):
        if getattr(software, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(group)
            continue

        if getattr(software, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(software)

        if hasattr(software, "x_mitre_aliases"):
            aliases = [tool.lower() for tool in software.x_mitre_aliases]
            facts.append(("tool", software.name.lower(), "toolAlias", "tool", aliases, "bidirectional"))

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Technqiues       relationship where relationship_type == "uses", points to
        #                    a target object with type == "attack-pattern"

        uses_techniques = [
            tech.name
            for tech in attack.related_to(software, relationship_type="uses")
            if tech.type in ("attack-pattern")
        ]

        facts.append(("tool", software.name, "usesTechnique", "technique", uses_techniques, "linked"))

    return (facts, notify)


def notify_cache(filename):
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


def add_to_cache(filename, entry):
    """
    Add entry to cache

    Args:
        filename(str):      Cache filename
        entry(str):         Cache entry
    """

    with open(filename, "a") as f:
        f.write(entry.strip())
        f.write("\n")


def send_notification(notify, notifycache, smtphost, sender, recipient):
    """
    Process revoked objects

    Args:
        notify(attack[]):   Array of revoked/deprecated Stix objects
        notifycache(str):   Filename of notify cache
        smtphost(str):      SMTP host used to notify of revoked/deprecated objects
        sender(str):        sender address used to notify of revoked/deprecated objects
        recipient(str):     recipient address used to notify of revoked/deprecated objects

    smtphost, sender AND recipient must be set to notify of revoked/deprecated objects

    """

    body = url + "\n\n"
    warning("[{}]".format(url))

    for obj in notify:
        # Add object to cache, so we will not be notified on the same object on the next run
        add_to_cache(notifycache, obj.id)

        if getattr(obj, "revoked", None):
            text = "revoked: {}:{}".format(obj.type, obj.name)

        elif getattr(obj, "x_mitre_deprecated", None):
            text = "deprecated: {}:{}".format(obj.type, obj.name)
        else:
            text = "ERROR obj is not deprecated or revoked: {}:{}".format(obj.type, obj.name)

        body += text + "\n"
        warning(text)

    if smtphost and recipient and sender:
        worker.sendmail(smtphost, sender, recipient, "Revoked/deprecated objects from MITRE/ATT&CK", body)
        info("Email sent to {}".format(recipient))
    else:
        error("--smtphost, --recipient and --sender must be set to send revoked/deprecated objects on email")


if __name__ == '__main__':
    args = parseargs()

    client = act.Act(
        args.act_baseurl,
        args.user_id,
        args.loglevel,
        args.logfile,
        "mitre-attack")

    for url in (MITRE_ENTERPRISE_ATTACK_URL, MITRE_MOBILE_ATTACK_URL, MITRE_PRE_ATTACK_URL):
        cache = notify_cache(args.notifycache)
        notify = []

        # Get attack dataset as Stix Memory Store
        attack = get_attack(url, args.proxy_string, args.timeout)

        (techniques, techniques_notify) = get_techniques(attack)
        (groups, groups_notify) = get_groups(attack)
        (software, software_notify) = get_software(attack)

        # Add facts to platform
        facts = techniques + groups + software
        for (source_type, source_values, fact_type, destination_type, destination_values, link_type) in facts:
            add_fact(client,
                     source_type,
                     source_values,
                     fact_type,
                     destination_type,
                     destination_values,
                     link_type)

        # Get revoked objects, excluding those in cache
        notify = [
            notify
            for notify in techniques_notify + groups_notify + software_notify
            if notify.id not in cache
        ]

        if notify:
            send_notification(notify, args.notifycache, args.smtphost, args.sender, args.recipient)
