#!/usr/bin/env python3

"""General ACT backend uploader. Reads facts as JSON
from the stdin, uploading accordingly"""

import argparse
import json
import sys
import time
import traceback
from logging import error, warning

import act.api

from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Generic uploader')
    parser.add_argument('--timing', action="store_true",
                        help="Add timing operations at warn level")

    return parser


def main(actapi: act.api.Act, timing: bool = False) -> None:
    """Process stdin, parse each separat line as a JSON structure and
    register a fact based on the structure. The form of input should
    be the on the form accepted by the ACT Rest API fact API."""

    handle_fact_time = []
    origins = set()

    for line in sys.stdin:
        data = json.loads(line)

        fact = actapi.fact(**data)
        try:
            started = time.time()
            act.api.helpers.handle_fact(fact)

            if fact.origin:
                origins.add(fact.origin.name)

            time_spent = time.time() - started
            handle_fact_time.append(time_spent)
            if timing:
                warning("Handle fact time: %s", round(time_spent, 2))
        except act.api.base.ValidationError as err:
            warning("ValidationError while storing objects: %s" % err)
        except act.api.base.ResponseError as err:
            error("ResponseError while storing objects: %s" % err)
            sys.exit(1)

    if timing:
        warning(
            "Total time (count:%s,total:%s,mean:%s,min:%s,max:%s,origins:%s)",
            len(handle_fact_time),
            round(sum(handle_fact_time), 2),
            round(sum(handle_fact_time)/len(handle_fact_time), 2),
            round(min(handle_fact_time), 2),
            round(max(handle_fact_time), 2),
            "+".join(origins)
        )


def main_log_error() -> None:
    "Call main() and log all exceptions as errors"
    try:
        # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
        # (or replace .config with $XDG_CONFIG_DIR if set)
        args = worker.handle_args(parseargs())
        actapi = worker.init_act(args)

        main(actapi, args.timing)
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
