import argparse
import itertools
import json
import pprint
import re
import sys
import traceback
from collections import defaultdict
from logging import error, info
from typing import Dict, List, Text

import act
import act.api
from act.workers.libs import worker
import os

def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Map tool aliases')
    parser.add_argument(
        '--threshold',
        type=float,
        default=0.5,
        help="Threshold for Jaccard index")
    parser.add_argument(
        '--submit',
        default=False,
        action="store_true",
        help="Submit alias to platform")
    parser.add_argument(
        '--exclude_tools',
        default="^\[placeholder\[[a-f0-9]{64}\]\]$",
        help="Tool patterns to exclude")
    return parser


def jaccard(set1: set, set2: set) -> float:
    il = float(len(set1.intersection(set2)))
    ul = float(len(set1.union(set2)))
    return il / ul


def search_tools(api: act.api.Act, ignore_pattern: Text) -> Dict:
    tools = defaultdict(list)
    objects = api.object_search(object_type="tool", limit=10000)
    for obj in objects:
        facts = api.fact_search(object_type="content", object_value=obj.value, limit=10000)
        for fact in facts:
            if re.match(ignore_pattern, fact.source_object.value):
                continue
            tools[obj.value].append(fact.source_object.value)
    return tools


def get_aliases(api: act.api.Act, tool_names: List) -> Dict:
    aliases = defaultdict(list)
    for tool in tool_names:
        result = api.fact_search(object_type="tool", fact_type="alias", object_value=tool)
        for fact in result:
            aliases[tool].append(fact.destination_object.value)
    return aliases


def handle_alias(api: act.api.Act, tool1: Text, tool2: Text, submit: bool, output_format: Text = "json"):
    try:
        fact = api.fact("alias") \
                    .bidirectional("tool", tool1, "tool", tool2)
        if submit:
            handle_fact(fact)
        elif output_format == "json":
            print(fact.json())
        else:
            print(fact)
    except act.api.base.ResponseError as e:
        error("Unable to create linked fact: %s" % e)


def process(tools: Dict, aliases: Dict, threshold: float) -> None:
    for tool1, tool2 in itertools.combinations(list(tools.keys()), 2):
        jaccard_index = jaccard(set(tools[tool1]), set(tools[tool2]))
        if jaccard_index > threshold and tool1 not in aliases[tool2]:
            yield tool1, tool2


def main() -> None:
    """Main function"""
    args = worker.handle_args(parseargs())
    actapi = worker.init_act(args)

    if not (args.act_baseurl and args.user_id):
        error("Worker must be configured with --act-baseurl and --userid")
        sys.exit(1)

    tools = search_tools(actapi, args.exclude_tools)
    aliases = get_aliases(actapi, list(tools.keys()))

    for tool1, tool2 in process(tools, aliases, args.threshold):
        handle_alias(actapi, tool1, tool2, args.submit, args.output_format)


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()