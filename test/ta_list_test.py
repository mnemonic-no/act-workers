import pytest
from update_ta_aliases_list import add_ta_to_map, add_ta_alias_to_map
import json

# testing update_ta_aliases_list.py


def test_add_ta_to_map():
    # reads file with objects from ACT
    with open('test/objects.json', 'r') as infile:
        ta = set(json.loads(infile.read()))

    ta_map = add_ta_to_map(ta)  # adds all objects to map.

    for i in ta:
        assert i in ta_map  # at alle elementer fra filen finnes i ta_map


def test_add_ta_alias_to_map():

    # reads file with objects from ACT
    with open('test/objects.json', 'r') as infile:
        ta = set(json.loads(infile.read()))

    ta_map = add_ta_to_map(ta)  # adds all objects to map.

    # reads file with facts from ACT
    with open('test/facts.json', 'r') as infile:
        data = json.loads(infile.read())
        ta_aliases = set()
        for i in data:
            ta1, ta2 = i[0], i[1]
            ta_aliases.add((ta1, ta2))

    ta_map = add_ta_alias_to_map(ta_aliases, ta_map)
    for i in ta_aliases:
        assert i[0], i[1] in ta_map  # at alle elementer i ta_aliases er på plass i ta_map
