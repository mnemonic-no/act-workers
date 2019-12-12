#!/usr/bin/env python3

"Search for objects and traverse graph for all results"

import argparse
import concurrent.futures
import configparser
import datetime
import inspect
import os
import re
import sys
from logging import error, info, warning
from typing import Any, Dict, Text

import dateparser

import act.api
from act.workers.libs import worker

# Inspect object search function to get list of valid arguments and their defaults
VALID_SEARCH_OPTIONS: Dict[str, Any] = {
    arg: parameter.default
    for arg, parameter in inspect.signature(act.api.Act.object_search).parameters.items()
    if arg != "self"
}

SEARCH_OPTIONS_FUNC: Dict = {
    "before": lambda ts: dateparser.parse(ts).strftime(act.api.ACT_TIME_FORMAT),
    "after": lambda ts: dateparser.parse(ts).strftime(act.api.ACT_TIME_FORMAT),
}


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Search Graph')
    parser.add_argument('--search-jobs', help="Search jobs (ini-file)")
    parser.add_argument(
        '--output-path',
        help="Output-path for result files (default=.)",
        default=".")
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help="Number of parallel workers for graph search")

    return parser


def parse_search_jobs(config_filename: Text) -> Dict:
    "Parse config with search jobs and return dictionary of section name and options"
    config = configparser.ConfigParser()
    config.read(config_filename)
    return {section: dict(config.items(section)) for section in config.sections()}


def traverse(api: act.api.Act, name: Text, weburl: Text, obj: act.api.obj.Object, query: Text, minfacts: int) -> Text:
    output = ""
    try:
        # Replace all whitespace that is not within quotes
        # https://stackoverflow.com/questions/9577930/regular-expression-to-select-all-whitespace-that-isnt-in-quotes

        query_url = re.sub(r'\s+(?=([^"]*"[^"]*")*[^"]*$)', '', query)
        info("{} -> {}".format(obj, query_url))
        res = api.object(obj.type, obj.value).traverse(query)

        facts = {str(obj) for obj in res if isinstance(obj, act.api.fact.Fact)}
        if len(facts) >= minfacts:
            output += """[{}:{}]\n{}/graph-query/{}/{}/{}\n""".format(
                name, obj, weburl, obj.type.name, obj.value, query_url)

            # String representation of all facts (joined with newlines)
            output += "\n".join(facts)

    except act.api.base.ResponseError as e:
        error("{}, {}, {}".format(e, obj, query))

    return output


def process(actapi: act.api.Act, output_path: Text, name: Text, options: Dict, workers: int) -> None:
    if "query" not in options:
        error("No query specified in {}, skipping".format(name))
        return

    # Extract query as separate option
    query = options["query"]
    blacklist = options.get("blacklist", "").split(",")
    object_value_re = options.get("object_value_re", r'.*')
    weburl = options.get("weburl", actapi.config.act_baseurl)
    minfacts = int(options.get("minfacts", 1))

    filename = os.path.join(
        output_path,
        "{}-{}.result".format(datetime.datetime.now().strftime("%Y-%m-%d-%H-%m"), name))

    info("Result will be written to {}".format(filename))

    with open(filename, "w") as f:

        # Construct search options from ini file
        search_options = {}

        for key, value in options.items():
            if key in ("query", "blacklist", "object_value_re", "weburl", "minfacts"):
                # Query/blacklist/object_value_re is not part of object search options
                # but passed on to traverse
                continue

            if key not in VALID_SEARCH_OPTIONS:
                error("Illegal query option ({}) specified in {}, skipping".format(key, name))
                return

            if key in SEARCH_OPTIONS_FUNC:
                search_options[key] = SEARCH_OPTIONS_FUNC[key](value)
            elif VALID_SEARCH_OPTIONS[key] == []:
                # Split values on comma (except escaped commas)
                search_options[key] = [value.strip() for value in re.split(r'(?<!\\),', value) if value]
            else:
                search_options[key] = value

        info("Search options: {}".format(search_options))

        try:
            objects = actapi.object_search(**search_options)
        except Exception:
            error("Fatal: object search exception: {}".format(search_options), exc_info=True)
            return

        if objects.size != objects.count:
            warning("Received only {}/{} objects".format(objects.size, objects.count))

        info("Received {} objects".format(objects.size))

        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:

            future_traverse = {
                executor.submit(traverse, actapi, name, weburl, obj, query, minfacts): str(obj)
                for obj in objects
                if (str(obj) not in blacklist) and re.search(object_value_re, obj.value)
            }

            for idx, future in enumerate(concurrent.futures.as_completed(future_traverse)):
                obj = future_traverse[future]
                try:
                    data = future.result()
                except Exception:
                    error("traverse exception: {}".format(obj), exc_info=True)
                    continue

                info("Progress: {}/{}".format(idx + 1, objects.size))

                if data:
                    f.write(data + "\n\n")
                    f.flush()


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)

    args = worker.handle_args(parseargs())
    actapi = worker.init_act(args)

    if not (args.act_baseurl and args.user_id):
        sys.stderr.write("Must specify --baseurl and --user-id\n")
        sys.exit(1)

    if not os.path.isfile(args.search_jobs):
        sys.stderr.write("File not found: {}\n".format(args.search_jobs))
        sys.exit(2)

    if not args.search_jobs:
        sys.stderr.write("Must specify config file with search jobs\n")
        sys.exit(2)

    try:
        for name, options in parse_search_jobs(args.search_jobs).items():
            process(actapi, args.output_path, name, options, args.workers)

    except Exception:
        error("Unhandled exception", exc_info=True)
        raise


if __name__ == '__main__':
    main_log_error()
