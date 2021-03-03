#!/usr/bin/env python3

"""

Worker for HAFNIUM threat_actor


"""

import argparse
import traceback
from logging import error

import act.api
from act.api.helpers import handle_fact

from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Mitre ATT&CK worker')

    return parser


def add_ta_techniques(client, output_format, threat_actor, techniques):
    """ Threat Actor Techniques """

    for technique in techniques:
        chain = act.api.fact.fact_chain(
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor),
            client.fact("attributedTo")
            .source("event", "*")
            .destination("incident", "*"),
            client.fact("classifiedAs")
            .source("event", "*")
            .destination("technique", technique)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_tools(client, output_format, threat_actor, tools):
    """ Threat Actor Tools """

    for tool in tools:
        chain = act.api.fact.fact_chain(
            client.fact("classifiedAs")
            .source("content", "*")
            .destination("tool", tool.lower()),
            client.fact("observedIn")
            .source("content", "*")
            .destination("event", "*"),
            client.fact("attributedTo")
            .source("event", "*")
            .destination("incident", "*"),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_sectors(client, output_format, threat_actor, sectors):
    for sector in sectors:
        # + law firms,  policy think tanks

        chain = act.api.fact.fact_chain(
            client.fact("targets")
            .source("incident", "*")
            .destination("sector", sector),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_target_country(client, output_format, threat_actor, target_countries):
    for target_country in target_countries:
        chain = act.api.fact.fact_chain(
            client.fact("targets")
            .source("incident", "*")
            .destination("country", target_country),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor)
        )

        for fact in chain:
            handle_fact(fact, output_format=output_format)


def add_ta_located_in(client, output_format, threat_actor, located_in):
    chain = act.api.fact.fact_chain(
        client.fact("locatedIn")
        .source("organization", "*")
        .destination("country", located_in),
        client.fact("attributedTo")
        .source("threatActor", threat_actor)
        .destination("organization", "*")
    )

    for fact in chain:
        handle_fact(fact, output_format=output_format)


def add_ta_campaign(client, output_format, threat_actor, campaign):
    chain = act.api.fact.fact_chain(
        client.fact("locatedIn")
        .source("incident", "*")
        .destination("campaign", campaign),
        client.fact("attributedTo")
        .source("threatActor", threat_actor)
        .destination("incident", "*")
    )

    for fact in chain:
        handle_fact(fact, output_format=output_format)


def main() -> None:
    """ Main function """

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    threat_actor = "HAFNIUM"

    add_ta_techniques(
        actapi,
        args.output_format,
        threat_actor,
        ("Obtain Capabilities",
         "OS Credential Dumping",
         "Exploit Public-Facing Application",
         "Archive Collected Data",
         "Acquire Infrastructure",
         "Application Layer Protocol",
         "Email Collection",
         "Exfiltration Over Web Service",
         "Create Account",
         "Remote Services"))

    add_ta_tools(
        actapi,
        args.output_format,
        threat_actor,
        ("PsExec",
         "Procdump",
         "7-Zip",
         "Nishang",
         "PowerCat",
         "WinRar",
         "SIMPLESEESHARP",
         "SPORTSBALL",
         "China Chopper",
         "ASPXSPY",
         "Covenant"))

    add_ta_sectors(
        actapi,
        args.output_format,
        threat_actor,
        ("pharmaceuticals", "education", "defense", "non-profit"))

    add_ta_target_country(
        actapi,
        args.output_format,
        threat_actor,
        ("China", "United States of America"))

    add_ta_located_in(actapi, args.output_format, threat_actor, "China")

    add_ta_campaign(actapi, args.output_format, threat_actor, "Operation Exchange Marauder")


def main_log_error() -> None:
    "Call main() and log all excetions  as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
