import re
from typing import Set, Text, Tuple

import stix2


class PatternNotSupported(Exception):
    pass


def expand_techniques(attack_pattern: stix2.v20.AttackPattern) -> Set[Text]:
    """Expand Mitre Attack Techniques from Stix Attack Pattern"""
    if not isinstance(attack_pattern, stix2.v20.AttackPattern):
        raise TypeError(f"{attack_pattern} is not an AttackPattern")

    return {
        ref.external_id
        for ref in attack_pattern.external_references
        if ref.source_name == "mitre-attack"
    }


def parse_single_stix_pattern(pattern: Text) -> Tuple[Text, Text]:

    """
    Extract type/value from Stix Indicator patterns like this:

        [domain-name:value = 'sampwn.anondns.net']
        [url:value = 'https://teamtnt.red']

    """

    parser = re.search(
        r"""
    ^\[                         # Opening bracket
        (?P<type>[^\s]+)
        \s
        =
        \s
    '(?P<value>([^'\\]|\\.)*)'  # Match all characters EXCEPT escaped single quote
    \]$                         # Closing bracket
    """,
        pattern,
        re.VERBOSE,
    )

    if not parser:
        raise PatternNotSupported(f"Unable to parse as single pattern: {pattern}")

    return parser.group("type").replace("'", ""), parser.group("value")
