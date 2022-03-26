from typing import Set, Text, Tuple

import stix2
from stix2patterns.v20.pattern import Pattern


class SingleStixPatternEqualError(Exception):
    pass


class NotEqualOperator(SingleStixPatternEqualError):
    pass


class MultipleComparisons(SingleStixPatternEqualError):
    pass


class TypesNotString(SingleStixPatternEqualError):
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


def single_stix_equal_pattern(pattern: Text) -> Tuple[Text, Text]:

    """
    Extract type/value from Stix Indicator patterns like this:

        [domain-name:value = 'sampwn.anondns.net']
        [url:value = 'https://teamtnt.red']

    """

    pattern_data = Pattern(pattern).inspect()
    comparisons = pattern_data.comparisons

    if len(comparisons) > 1:
        raise MultipleComparisons

    main_type = list(comparisons.keys())[0]

    if len(comparisons[main_type]) > 1:
        raise MultipleComparisons

    (sub_type, oper, value) = comparisons[main_type][0]

    if oper != "=":
        raise NotEqualOperator

    if not all([isinstance(t, str) for t in sub_type]):
        raise TypesNotString

    pattern_type = f"{main_type}:{'.'.join(sub_type)}"

    return pattern_type, value.strip("'")
