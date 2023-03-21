from typing import List

import act.api
from act.api.helpers import Act, handle_facts


def handle_ta_techniques(
    client: Act, output_format: str, threat_actor: str, techniques: List[str]
) -> None:
    """Threat Actor Techniques"""

    for technique in techniques:
        handle_facts(
            act.api.fact.fact_chain(
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", threat_actor),
                client.fact("observedIn")
                .source("technique", technique)
                .destination("incident", "*"),
            ),
            output_format=output_format,
        )


def handle_ta_tools(
    client: Act, output_format: str, threat_actor: str, tools: List[str]
) -> None:
    """Threat Actor Tools"""

    for tool in tools:
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
                .destination("threatActor", threat_actor),
            ),
            output_format=output_format,
        )


def handle_ta_sectors(
    client: Act, output_format: str, threat_actor: str, sectors: List[str]
) -> None:
    """Threat Actor Sectors"""
    for sector in sectors:
        handle_facts(
            act.api.fact.fact_chain(
                client.fact("targets")
                .source("incident", "*")
                .destination("organization", "*"),
                client.fact("memberOf")
                .source("organization", "*")
                .destination("sector", sector),
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", threat_actor),
            ),
            output_format=output_format,
        )


def handle_ta_target_country(
    client: Act, output_format: str, threat_actor: str, target_countries: List[str]
) -> None:
    """Threat actor target countries"""
    for target_country in target_countries:
        handle_facts(
            act.api.fact.fact_chain(
                client.fact("targets")
                .source("incident", "*")
                .destination("organization", "*"),
                client.fact("locatedIn")
                .source("organization", "*")
                .destination("country", target_country),
                client.fact("attributedTo")
                .source("incident", "*")
                .destination("threatActor", threat_actor),
            ),
            output_format=output_format,
        )


def handle_ta_located_in(
    client: Act, output_format: str, threat_actor: str, located_in: str
) -> None:
    """Threat actor located in"""
    handle_facts(
        act.api.fact.fact_chain(
            client.fact("locatedIn")
            .source("organization", "*")
            .destination("country", located_in),
            client.fact("attributedTo")
            .source("threatActor", threat_actor)
            .destination("organization", "*"),
        ),
        output_format=output_format,
    )


def handle_ta_campaign(
    client: Act, output_format: str, threat_actor: str, campaign: str
) -> None:
    """Threat Actor Campaign"""
    handle_facts(
        act.api.fact.fact_chain(
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("campaign", campaign),
            client.fact("attributedTo")
            .source("incident", "*")
            .destination("threatActor", threat_actor),
        ),
        output_format=output_format,
    )
