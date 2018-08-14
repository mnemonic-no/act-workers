#!/usr/bin/env python3

"""

Worker for Mitre ATT&CK, using the STIX implementation available here:

    https://github.com/mitre/cti

    ATT&CK concept	STIX Object type        ACT object
    =========================================================
    Technique	        attack-pattern          technique
    Group	        intrusion-set           threatActor
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
DEFAULT_REVOKED_CACHE = os.path.join(os.environ["HOME"], "act-mitre-attack-revoked.cache")


def parseargs():
    """ Parse arguments """
    parser = worker.parseargs('Mitre ATT&CK worker')
    parser.add_argument('--smtphost', dest='smtphost', help="SMTP host used to send revoked objects")
    parser.add_argument('--sender', dest='sender', help="Sender address used to send revoked objects")
    parser.add_argument('--recipient', dest='recipient', help="Recipient address used to send revoked objects")
    parser.add_argument('--revokedcache', dest='revokedcache', help="Cache for revoked objects", default=DEFAULT_REVOKED_CACHE)
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


def fact(client, source_type, source_values, fact_type, destination_type, destination_values, link_type="linked"):
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


def process_techniques(client, attack):
    """
        extract objects/facts related to ATT&CK techniques
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        client(act.Act):      Act instance
        attack (stix2):       Stix attack instance

    """

    revoked = []

    for technique in attack.query([Filter('type', '=', 'attack-pattern')]):
        if getattr(technique, "revoked", None) or getattr(technique, "x_mitre_deprecated", None):
            revoked.append(technique)
            continue

        # Mitre ATT&CK Tactics are implemented in STIX as kill chain phases with kill_chain_name "mitre-attack"
        tactics = [
            tactic.phase_name
            for tactic in technique.kill_chain_phases
            if tactic.kill_chain_name == "mitre-attack"
        ]

        fact(client, "tactic", tactics, "usesTechnique", "technique", technique.name)

    return revoked


def process_groups(client, attack):
    """
        extract objects/facts related to ATT&CK Groups
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        client(act.Act):      Act instance
        attack (stix2):       Stix attack instance

    """

    revoked = []

    for group in attack.query([Filter('type', '=', 'intrusion-set')]):
        # Is group revoked/deprecated?
        if getattr(group, "revoked", None) or getattr(group, "x_mitre_deprecated", None):
            revoked.append(group)
            continue

        if getattr(group, "aliases", None):
            fact(client, "threatActor", group.name, "threatActorAlias", "threatActor", group.aliases, link_type="bidirectional")

        uses_tools = [
            tool.name.lower()
            for tool in attack.related_to(group, relationship_type="uses")
            if tool.type in ("malware", "tool")
        ]

        uses_techniques = [
            tech.name
            for tech in attack.related_to(group, relationship_type="uses")
            if tech.type in ("attack-pattern")
        ]

        fact(client, "threatActor", group.name, "usesTechnique", "technique", uses_techniques)
        fact(client, "threatActor", group.name, "usesTool", "tool", uses_tools)

    return revoked


def process_software(client, attack):
    """
        extract objects/facts related to ATT&CK Software
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        client(act.Act):      Act instance
        attack (stix2):       Stix attack instance

    """

    revoked = []

    for software in attack.query([Filter('type', 'in', ['tool', "malware"])]):
        # Is group revoked/deprecated?
        if getattr(software, "revoked", None) or getattr(software, "x_mitre_deprecated", None):
            revoked.append(software)
            continue

        if hasattr(software, "x_mitre_aliases"):
            aliases = [tool.lower() for tool in software.x_mitre_aliases]
            fact(client, "tool", software.name.lower(), "toolAlias", "tool", aliases, link_type="bidirectional")

        uses_techniques = [
            tech.name
            for tech in attack.related_to(software, relationship_type="uses")
            if tech.type in ("attack-pattern")
        ]

        fact(client, "tool", software.name, "usesTechnique", "technique", uses_techniques)

    return revoked


def revoked_cache(filename):
    """
    Read revoked cache from filename
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


def process_revoked(revoked, revokedcache, smtphost, sender, recipient):
    """
    Process revoked objects

    Args:
        revoked(attack[]):  Array of revoked Stix objects
        revokedcache(str):  Filename of revoked cache
        smtphost(str):      SMTP host used to notify of revoked/deprecated objects
        sender(str):        sender address used to notify of revoked/deprecated objects
        recipient(str):     recipient address used to notify of revoked/deprecated objects

    smtphost, sender AND recipient must be set to notify of revoked/deprecated objects

    """

    if not revoked:
        return

    body = url + "\n\n"
    warning("[{}]".format(url))

    for obj in revoked:
        # Add object to cache, so we will not be notified on the same object on the next run
        add_to_cache(revokedcache, obj.id)
        text = "revoked/deprecated: {}:{}".format(obj.type, obj.name)
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
        cache = revoked_cache(args.revokedcache)
        revoked = []

        attack = get_attack(url, args.proxy_string, args.timeout)
        technique_revoked = process_techniques(client, attack)
        groups_revoked = process_groups(client, attack)
        software_revoked = process_software(client, attack)

        # Get revoked objects, excluding those in cache
        revoked = [
            revoked
            for revoked in technique_revoked + groups_revoked + software_revoked
            if revoked.id not in cache
        ]

        process_revoked(revoked, args.revokedcache, args.smtphost, args.sender, args.recipient)
