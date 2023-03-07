#!/usr/bin/env python3

"""General ACT backend uploader. Reads facts as JSON
from the stdin, uploading accordingly"""

import argparse
import json
import sys
import time
import traceback
from logging import error, warning
from typing import Iterable, Text

import act.api
from act.api.libs import cli

from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """Parse arguments"""
    parser = worker.parseargs("Generic uploader")
    parser.add_argument(
        "--allow-default-origin", action="store_true", help="Allow facts without origin"
    )
    parser.add_argument(
        "--timing", action="store_true", help="Add timing operations at warn level"
    )

    parser.add_argument(
        "--no-exit-on-error", action="store_true", help="Log errors and continue"
    )

    parser.add_argument(
        "--no-format",
        action="store_true",
        help="Do not format facts with default formatter",
    )

    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Do not validate facts with default types",
    )

    return parser


def uploader(
    actapi: act.api.Act,
    iterator: Iterable[Text],
    timing: bool = False,
    allow_default_origin: bool = False,
    no_exit_on_error: bool = False,
) -> None:
    """Process stdin, parse each separat line as a JSON structure and
    register a fact based on the structure. The form of input should
    be the on the form accepted by the ACT Rest API fact API."""

    handle_fact_time = []
    origins = set()
    facts = {}
    metafacts = set()
    max_retries = 10

    for line in iterator:
        try:
            data = json.loads(line)
        except json.decoder.JSONDecodeError:
            error("Error decoding json: %s" % line)
            continue

        # Create either Fact or MetaFact, if we have the inReferenceTo field populated or not
        fact = (
            actapi.meta_fact(**data) if "inReferenceTo" in data else actapi.fact(**data)
        )

        if not allow_default_origin:
            if not (fact.origin and (fact.origin.id or fact.origin.name)):
                error("Origin not specified: %s", fact)
                continue

        started = time.time()

        # If this is a meta fact, save for later upload
        if isinstance(fact, act.api.fact.MetaFact):
            metafacts.add(fact)
            continue

        # Handle fact
        # Fact will be added to the platform if base_url is configured
        # The returned fact will be populated with a fact id
        # and default values from the platform
        try:

            # Retry as long as we get ServiceTimeout (max_retries times)
            for retry in range(max_retries):
                try:
                    fact_copy = act.api.helpers.handle_fact(fact)
                    break
                except act.api.base.ServiceTimeout:
                    warning(
                        "ServiceTimeout while storing objects (%s/%s)",
                        retry,
                        max_retries,
                    )
                    if retry < max_retries:
                        time.sleep(retry * 3)
            else:
                error("Max retries reached, exit")
                sys.exit(2)

        except act.api.base.ValidationError as err:
            warning("ValidationError while storing objects: %s" % err)
            continue
        except act.api.base.ResponseError as err:
            error("ResponseError while storing objects: %s" % err)

            if not no_exit_on_error:
                sys.exit(1)

            continue

        # handle_fact() will return None if fact does not validate
        if fact_copy is None:
            warning("No fact returned from platform for: %s" % data)
            continue

        # Add cache for facts to be used to populate id in meta facts
        if isinstance(fact, act.api.fact.Fact):
            facts[fact] = fact_copy.id

        # Keep list of all known origins
        if fact.origin:
            origins.add(fact.origin.name)

        time_spent = time.time() - started
        handle_fact_time.append(time_spent)
        if timing:
            warning("Handle fact time: %s", round(time_spent, 2))

    for fact in metafacts:
        if fact.in_reference_to not in facts:
            error(
                "Recieved metafact that references unknown fact. "
                "This error can occur if the fact is not submitted in the same file "
                "or the fact fails to validate."
            )
            continue

        # Update ID of referenced fact from cache
        fact.in_reference_to.id = facts[fact.in_reference_to]
        try:
            act.api.helpers.handle_fact(fact)
        except act.api.base.ValidationError as err:
            warning("ValidationError while storing objects: %s" % err)
            continue
        except act.api.base.ResponseError as err:
            error("ResponseError while storing objects: %s" % err)
            sys.exit(1)

    if timing and handle_fact_time:
        warning(
            "Total time (count:%s,total:%s,mean:%s,min:%s,max:%s,origins:%s)",
            len(handle_fact_time),
            round(sum(handle_fact_time), 2),
            round(sum(handle_fact_time) / len(handle_fact_time), 2),
            round(min(handle_fact_time), 2),
            round(max(handle_fact_time), 2),
            "+".join(origins),
        )


def main_log_error() -> None:
    "Call main() and log all exceptions as errors"
    try:
        # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
        # (or replace .config with $XDG_CONFIG_DIR if set)
        args = cli.handle_args(parseargs())
        actapi = worker.init_act(
            args, no_format=args.no_format, no_validate=args.no_validate
        )

        uploader(
            actapi,
            sys.stdin,
            args.timing,
            args.allow_default_origin,
            args.no_exit_on_error,
        )
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
