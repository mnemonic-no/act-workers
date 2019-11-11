#!/usr/bin/env python3

"""Origin client. Manage origins """

import argparse
import re
import sys
import traceback
from logging import error
from typing import Text

import act.api
from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Manage origins')
    parser.add_argument("--list", action="store_true", help="List origins")
    parser.add_argument("--add", action="store_true", help="List origins")
    parser.add_argument("--delete", action="store_true", help="List origins")

    # Trust is converted to float before sending a request to the platform
    # and since this value can come from an ini file (where it will be a string)
    # We keep the value as a string here
    parser.add_argument("--default-trust", default="0.8", help="Default trust")

    return parser


def fatal(msg: Text, exit_code: int = 1) -> None:
    "Output message as error and exit"
    error(msg)
    sys.exit(exit_code)


def add_origin(actapi: act.api.Act, default_trust: Text) -> None:
    sys.stdout.write("Origin name: ")
    name = input()
    sys.stdout.write("Origin description: ")
    description = input()
    sys.stdout.write("Origin trust (float 0.0-1.0. Default=0.8): ")
    trust = input()
    sys.stdout.write("Origin organization (UUID): ")
    organization = input()

    if not trust:
        trust = default_trust

    try:
        trust = float(trust)
    except ValueError:
        fatal("Unable to convert {} to float".format(trust))

    if not (trust >= 0.0 and trust <= 1.0):
        fatal("Trust must be between 0.0 and 1.0")

    params = {
        "name": name,
        "description": description,
        "trust": trust,
    }

    if organization:
        if not re.search(act.api.RE_UUID_MATCH, organization):
            fatal("Organization must be a valid UUID")

        params["organization"] = organization

    origin = actapi.origin(**params)
    origin.add()

    print("Origin added:")
    print(origin)


def origin_handler(actapi: act.api.Act, args: argparse.Namespace) -> None:
    "handle origins"

    try:
        if args.list:
            for origin in actapi.get_origins():
                print(origin)

        if args.add:
            add_origin(actapi, default_trust=args.default_trust)

        if args.delete:
            actapi.api_delete("v1/origin/uuid/{}".format(args.origin_id))

            print("Origin deleted: {}".format(args.origin_id))

    except act.api.base.ResponseError as err:
        error("ResponseError while connecting to platform: %s" % err)


def main() -> None:
    "main function"
    try:
        # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
        # (or replace .config with $XDG_CONFIG_DIR if set)
        args = worker.handle_args(parseargs())

        if not (args.act_baseurl and args.user_id):
            fatal("--act-baseurl and --user-id must be specified")

        if not (args.list or args.add or args.delete):
            fatal("Specify either --list, --add or --delete")

        if (args.delete) and not (args.origin_id):
            fatal("Specify --origin-id to delete an origin")

        actapi = worker.init_act(args)
        origin_handler(actapi, args)
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main()
