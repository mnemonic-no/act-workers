#!/usr/bin/env python3

"""Worker module polling events from argus incidents"""

import argparse
import os
import socket
import sys
import time
import traceback
from logging import debug, error, info
from typing import Any, Dict, Generator, Optional, Text, cast, List

import caep
import requests
import urllib3

import act.api
from act.workers.libs import argus, mnemonic, worker

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('ARGUS Case enrichment')
    parser.add_argument('--argus-baseurl', dest='argus_baseurl',
                        default="https://api.mnemonic.no/", help="Argus API host")
    parser.add_argument('--argus-timeout', dest='timeout', type=int,
                        default=300, help="Timeout")
    parser.add_argument('--content-props',
                        default="file.sha256,process.sha256", help="Comma separated list of properties that represents a content object")
    parser.add_argument('--hash-props',
                        default="file.md5,process.md5,file.sha1,process.sha1,file.sha512,process.sha512", help="Comma separated list of properties that represents a hash")
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
    """Query the argus for events associated to cases.
    argus_baseurl - the url to the ARGUS api (https://api.mnemonic.no)
    apikey - Argus API key
    timeout - timeout towards API
    proxy_string - proxy string for the request
    """

    # Batch size
    limit = 2000

    # Use start time 1w prior to lastUpdated timestamp
    # Events can have "old" startTimestamp if they are delayed into argus.
    # lastUpdateTimstamp = timestamp when event is added to Argus
    # startTimeTimstamp = original timestamp of the event
    start_time = last_update - 3600 * 24 * 7 * 1000

    try:
        criteria = {
            "lastUpdatedTimestamp": last_update,
            "startTimestamp": start_time,
            "sortBy": ["lastUpdated"],
            "includeFlags": ["NOTIFIED"],
            "limit": limit,
            # Do not include events that are associated to incidents from streaming filter
            "excludeFlags": ["ASSOCIATED_TO_CASE_BY_FILTER"]
        }

        headers = {
            "Argus-API-Key": apikey
        }

        # Do query in batches and yield events
        yield from mnemonic.batch_query(
            "POST",
            "{}/events/v1/aggregated/search".format(argus_baseurl.rstrip("/")),
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
        caep.get_cache_dir(worker.worker_name(), create=True),
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
        caep.get_cache_dir(worker.worker_name(), create=True),
        "last_update")

    # Write last update timestamp to disk
    with open(cache_filename, "w") as f:
        f.write(str(last_update))


# pylint: disable=too-many-arguments
def process(api: act.api.Act, args: argparse.Namespace) -> None:
    """ Get events associated to cases since last update """

    last_update: Optional[int] = args.last_update
    content_props: List[Text] = [prop.strip() for prop in args.content_props.split(",")]
    hash_props: List[Text] = [prop.strip() for prop in args.hash_props.split(",")]

    # Last update is not specified, get last_update from file (cache)
    if not last_update:
        last_update = get_last_update()

    # Get events
    for counter, event in enumerate(event_case_query(
            args.argus_baseurl,
            args.argus_apikey,
            last_update,
            timeout=args.timeout, proxy_string=args.proxy_string)):

        # Result is sorted by lastUpdateTimestamp, so we update
        # last_update from the event
        last_update = cast(int, event["lastUpdatedTimestamp"])

        # Create facts from event
        argus.handle_argus_event(api, event, content_props, hash_props, args.output_format)

        # For every Nth event, update last updated event
        if (counter % 1000) == 0:
            info("Offset: {}, last_update: {}".format(
                counter,
                time.asctime(time.localtime(last_update / 1000))))
            update_last_update(last_update)

    # Make sure last_update is updated
    update_last_update(last_update)


def main() -> None:
    " main function "

    # Look for default ini file in "/etc/actworkers.ini" and
    # ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)

    args = worker.handle_args(parseargs())

    if not args.argus_apikey:
        worker.fatal("You must specify --apikey on command line or in config file")

    actapi = worker.init_act(args)
    process(actapi, args)

def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
