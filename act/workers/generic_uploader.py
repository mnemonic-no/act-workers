#!/usr/bin/env python3

"""General ACT backend uploader. Reads facts as JSON
from the stdin, uploading accordingly"""

import json
import os
import sys
import traceback
from logging import error

import act.api
from act.workers.libs import worker


def main(actapi: act.api.Act) -> None:
    """Process stdin, parse each separat line as a JSON structure and
    register a fact based on the structure. The form of input should
    be the on the form accepted by the ACT Rest API fact API."""

    for line in sys.stdin:
        data = json.loads(line)

        fact = actapi.fact(**data)
        try:
            fact.add()
        except act.api.base.ResponseError as err:
            error("ResponseError while storing objects: %s" % err)


def main_log_error() -> None:
    "Call main() and log all exceptions as errors"
    try:
        # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
        # (or replace .config with $XDG_CONFIG_DIR if set)
        args = worker.handle_args(worker.parseargs("Generic uploader"))
        actapi = worker.init_act(args)

        main(actapi)
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
