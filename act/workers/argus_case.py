#!/usr/bin/env python3

"""Worker module polling events from argus incidents"""

import argparse
import os
import socket
import sys
import time
import traceback
from logging import debug, error, info
from typing import Any, Dict, Generator, Optional, Text, cast

import requests
import urllib3

import act.api
from act.workers.libs import argus, worker

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('ARGUS Case enrichment')
    parser.add_argument('--argus-baseurl', dest='argus_baseurl',
                        default="https://api.mnemonic.no/", help="Argus API host")
    parser.add_argument('--argus-timeout', dest='timeout', type=int,
                        default=300, help="Timeout")
    parser.add_argument('--last-update', type=int, help="Last updated timestamp (epoc, seconds). Default - use now-1w first time, and start on last retrieved event at next run.")
    parser.add_argument('--argus-apikey', dest='argus_apikey',
                        help="Argus API key")

    return parser


def event_case_query(
        argus_baseurl: Text,
        apikey: Text,
        last_update: int,
        timeout: int,
        proxy_string: Optional[Text] = None) -> Generator[Dict[str, Any], None, None]:
    """Query the passivedns result of an address.
    argus_baseurl - the url to the passivedns api (https://api.mnemonic.no)
    apikey - Argus API key with the passivedns role (minimum)
    timeout - timeout towards API
    """

    limit = 2000

    start_time = last_update - 3600 * 24 * 7 * 1000

    try:
        criteria = {
            "lastUpdatedTimestamp": last_update,
            "startTimestamp": start_time,
            "sortBy": ["lastUpdated"],
            "includeFlags": ["NOTIFIED"],
            "limit": limit,
            "excludeFlags": ["ASSOCIATED_TO_CASE_BY_FILTER"]  # Do include events that are associted to incident by streaming filter
        }

        argus_url = "{}/events/v1/aggregated/search".format(argus_baseurl.rstrip("/"))

        headers = {
            "Argus-API-Key": apikey
        }

        yield from argus.batch_query(
            "POST",
            argus_url,
            headers=headers,
            timeout=timeout,
            json_params=criteria,
            proxy_string=proxy_string)

    except (urllib3.exceptions.ReadTimeoutError,
            requests.exceptions.ReadTimeout,
            socket.timeout) as err:
        error("Timeout ({0.__class__.__name__})".format(err))


def get_last_update() -> int:
    "Get last update from disk (~/.cache/<worker_name>/last_update)"
    cache_filename: Text = os.path.join(
        worker.get_cache_dir(worker.worker_name(), create=True),
        "last_update")

    if os.path.isfile(cache_filename):
        # Read last_update from last recorded succsfully recieved event
        with open(cache_filename) as f:
            last_update = int(f.read().strip())
            debug("last update starting at {}".format(last_update))
    else:
        # last_update not specified, set to now-1w
        last_update = int((time.time() - 3600 * 24 * 7) * 1000)
        info("last update not specified, autoconfigured as {}".format(last_update))

    return last_update


def update_last_update(last_update: int) -> None:
    "Write last update from disk (~/.cache/<worker_name>/last_update)"
    cache_filename: Text = os.path.join(
        worker.get_cache_dir(worker.worker_name(), create=True),
        "last_update")

    # Write last update timestamp to disk
    with open(cache_filename, "w") as f:
        f.write(str(last_update))


# pylint: disable=too-many-arguments
def process(
        api: act.api.Act,
        argus_baseurl: Text,
        apikey: Text,
        last_update: Optional[int],
        timeout: int = 299,
        proxy_string: Optional[Text] = None,
        output_format: Text = "json") -> None:
    """Read queries from stdin, resolve each one through passivedns
    printing generic_uploader data to stdout"""

    if not last_update:
        last_update = get_last_update()

    for counter, event in enumerate(event_case_query(
            argus_baseurl,
            apikey,
            last_update,
            timeout=timeout, proxy_string=proxy_string)):

        # Result is sorted by lastUpdateTimestamp, so we update
        # lastUpdateTimestamp to the value from the event
        last_update = cast(int, event["lastUpdatedTimestamp"])

        # Handle facts from event
        argus.handle_argus_event(api, event, output_format)

        # For every Nth event, update last updated event
        if (counter % 1000) == 0:
            info("Offset: {}, last_update: {}".format(counter, last_update))
            update_last_update(last_update)

    update_last_update(last_update)


def main() -> None:
    " main function "

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    auth = None
    if args.http_user:
        auth = (args.http_user, args.http_password)

    if not args.argus_apikey:
        sys.stderr.write("You must specify --apikey on command line or in config file\n")
        sys.exit(1)

    actapi = act.api.Act(
        args.act_baseurl,
        args.user_id,
        args.loglevel,
        args.logfile,
        worker.worker_name(),
        requests_common_kwargs={'auth': auth})

    process(
        actapi,
        args.argus_baseurl,
        args.argus_apikey,
        args.last_update,
        args.timeout,
        args.proxy_string,
        args.output_format)


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
