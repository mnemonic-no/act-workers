#!/usr/bin/env python3

"""General ACT backend uploader. Reads facts as JSON
from the stdin, uploading accordingly"""

from logging import error
import traceback
import argparse
import json
import sys
import act.api


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='PDNS enrichment')
    parser.add_argument('--userid', dest='user_id', required=True,
                        help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True,
                        help='ACT API URI')
    parser.add_argument("--logfile", dest="logfile",
                        help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")

    return parser.parse_args()


def main(actapi):
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
        ARGS = parseargs()

        actapi = act.api.Act(ARGS.act_baseurl, ARGS.user_id, ARGS.loglevel, ARGS.logfile, "generic-uploader")
        main(actapi)
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
