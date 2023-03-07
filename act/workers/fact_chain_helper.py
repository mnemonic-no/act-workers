#!/usr/bin/env python3

"""Fact chain creator helper worker for the ACT platform

Copyright 2021 the ACT project <opensource@mnemonic.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import argparse
import json
import pathlib
import sys
import traceback
from logging import error
from typing import List, Optional, Set, Text, TextIO, Tuple

import act.api
from act.api.helpers import handle_fact
from act.api.libs import cli
from act.types import types

from act.workers import worker_config
from act.workers.libs import worker


class Node:
    """Node in a graph"""

    def __init__(self, name: Text) -> None:
        self.name = name
        self.distance = sys.maxsize
        self.visited = False
        self.neighbours: List[Tuple[Node, int, Text, Text]] = []
        self.previous_direction: Optional[Text] = None
        self.previous_object: Optional[Node] = None
        self.previous_fact: Optional[Text] = None


def path(current_node: Node) -> List[Node]:
    """Backtrack the actuall path after a path is found, rebuilding the
    list of nodes"""

    if not current_node.previous_object:
        return [current_node]

    return path(current_node.previous_object) + [current_node]


def dijkstra(graph: Set[Node], start: Node, stop: Node) -> List[Node]:
    """Compute the shortest path through the types"""

    current: Optional[Node] = start
    start.distance = 0
    unvisited = graph.copy()

    while True:
        if not current:
            return []
        for neighbour, distance, fact, direction in current.neighbours:
            if neighbour.visited:
                continue
            cost = current.distance + distance
            if neighbour.distance >= cost:
                neighbour.distance = cost
                neighbour.previous_object = current
                neighbour.previous_fact = fact
                neighbour.previous_direction = direction

        current.visited = True
        unvisited.remove(current)

        if stop.visited:
            return path(stop)

        current = None
        for node in unvisited:
            if current is None:
                current = node
                continue
            if node.distance < current.distance:
                current = node

        if current and current.distance == sys.maxsize:
            return []


def graph_from_type_def(
    typedef: TextIO, avoids: List[Text], includes: List[Text], avoid_value: int
) -> Set[Node]:
    """Build a graph from a type definition file"""

    typedef.seek(0)
    data = json.load(typedef)

    nodes = dict()
    for fact in data:
        for binding in fact["objectBindings"]:

            if (
                "destinationObjectType" not in binding
                or "sourceObjectType" not in binding
            ):
                continue  # No point in traversing one legged facts

            fact_name = fact["name"]
            dest_objects = binding["destinationObjectType"]
            src_objects = binding["sourceObjectType"]

            if isinstance(dest_objects, str):
                dest_objects = [dest_objects]
            if isinstance(src_objects, str):
                src_objects = [src_objects]

            for dest_object in dest_objects:
                for src_object in src_objects:
                    if dest_object == src_object:
                        continue  # no point in traversing through it self

                    cost = 10

                    if (
                        fact_name in includes
                        or dest_object in includes
                        or src_object in includes
                    ):
                        cost = -100

                    # Avoid overwrites and takes precedence over includes
                    if (
                        fact_name in avoids
                        or dest_object in avoids
                        or src_object in avoids
                    ):
                        cost = 10 * avoid_value

                    if dest_object not in nodes:
                        nodes[dest_object] = Node(dest_object)
                    if src_object not in nodes:
                        nodes[src_object] = Node(src_object)
                    nodes[dest_object].neighbours.append(
                        (nodes[src_object], cost, fact_name, "<")
                    )
                    nodes[src_object].neighbours.append(
                        (nodes[dest_object], cost, fact_name, ">")
                    )

    return set(nodes.values())


def fact_type_value(data: Text) -> Tuple[Text, Text]:
    """Split the argument into fact type and value"""

    typ, val = data.split("/", 1)

    return typ, val


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs("ACT Fact Chain Helper")
    parser.add_argument(
        "--start",
        type=fact_type_value,
        help="Start type/value (i.e. threatActor/apt21)",
    )
    parser.add_argument(
        "--end", type=fact_type_value, help="End type/value (i.e. tool/zeus)"
    )
    parser.add_argument(
        "--avoid",
        type=worker_config.string_list,
        default=[],
        help="List of fact- or object- types to avoid",
    )
    parser.add_argument(
        "--include",
        type=worker_config.string_list,
        default=[],
        help="List of fact- or object- types to include",
    )
    parser.add_argument(
        "--fact-type-definition",
        type=str,
        default=types.etc_file("fact-types.json"),
        help='fact definition file. default="fact-types.json"',
    )
    parser.add_argument(
        "--avoid-cost",
        type=int,
        default=3,
        help="multiplier used to increase cost of avoided objects or facts. Default=3",
    )

    return parser


def find_start_and_end_nodes(
    graph: Set[Node], start_name: Text, end_name: Text
) -> Tuple[Optional[Node], Optional[Node]]:
    """search through graph looking for nodes with the provded names"""

    start = None
    end = None

    for node in graph:
        if node.name == start_name:
            start = node
        if node.name == end_name:
            end = node

    return start, end


def fact_chain_from_path_result(
    actapi: act.api.Act,
    res: List[Node],
    start: Node,
    end: Node,
    start_value: Text,
    end_value: Text,
) -> List[act.api.fact.FactType]:

    facts: List[act.api.fact.FactType] = []
    prev = None
    value = "*"

    for node in res:
        if prev is None:
            prev = node
            value = start_value if prev.name == start.name else "*"
            continue

        if end.name == node.name:
            value = end_value

        if node.previous_direction == ">":
            if node == end:
                facts.append(
                    actapi.fact(node.previous_fact)
                    .source(prev.name, "*")
                    .destination(node.name, value)
                )
            else:
                facts.append(
                    actapi.fact(node.previous_fact)
                    .source(prev.name, value)
                    .destination(node.name, "*")
                )
        else:
            if node == end:
                facts.append(
                    actapi.fact(node.previous_fact)
                    .destination(prev.name, "*")
                    .source(node.name, value)
                )
            else:
                facts.append(
                    actapi.fact(node.previous_fact)
                    .destination(prev.name, value)
                    .source(node.name, "*")
                )
        prev = node

        value = "*"

    fact_chain: List[act.api.fact.FactType] = act.api.fact.fact_chain(*facts)

    return fact_chain


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    actapi = worker.init_act(args)

    fact_type_definition_path = (
        pathlib.Path(args.fact_type_definition).expanduser().resolve()
    )

    if not fact_type_definition_path.is_file():
        print(f"{fact_type_definition_path} is not a file.")
        sys.exit(1)

    with fact_type_definition_path.open() as typedef:
        graph = graph_from_type_def(typedef, args.avoid, args.include, args.avoid_cost)

    start_type, start_value = args.start
    end_type, end_value = args.end

    start, end = find_start_and_end_nodes(graph, start_type, end_type)

    if not start:
        print(f"{start_type} is not an object type")
        sys.exit(1)

    if not end:
        print(f"{end_type} is not an object type")
        sys.exit(1)

    res = dijkstra(graph, start, end)

    chain = fact_chain_from_path_result(actapi, res, start, end, start_value, end_value)

    for fact in chain:
        handle_fact(fact, output_format=args.output_format)


def main_log_error() -> None:
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
