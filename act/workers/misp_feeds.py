#!/usr/bin/env python3.6
"""MISP feed worker pulling down feeds in misp_feeds.txt
and adding data to the platform"""

import argparse
import hashlib
import json
import os
import sys
import traceback
from logging import error, info
from typing import Dict, Generator, Optional, Text

import requests

import act
import act.api.helpers
from act.workers.libs import misp, worker

try:
    import urlparse
except ModuleNotFoundError:  # Python3
    import urllib.parse as urlparse  # type: ignore


def parseargs() -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = worker.parseargs('Get MISP feeds from MISP sharing directories')

    parser.add_argument('--manifest-dir', default=worker.get_cache_dir('misp_manifest'),
                        help='The directory to store latest manifests')

    return parser


def verify_manifest_dir(manifest_dir: Text) -> None:
    """Verify that the directory structure exists and that there is
    always a feed file (Even empty)"""

    # Manifest is at default location - create directory if it does not exists
    if manifest_dir == worker.get_cache_dir('misp_manifest'):
        worker.get_cache_dir('misp_manifest', create=True)

    # If there is specified a manifest directory in the .ini file we
    # verify that it exists (or fail hard). If no such directory
    # is defined, we default to using $XDG_CACHE_DIR and create a new
    # 'misp_maifest' directory there.
    if not os.path.isdir(manifest_dir):
        print("Could not open manifest directory:", manifest_dir)
        sys.exit(1)

    # Check that the misp_feeds.txt file actually exists. If not 'touch'
    # the file to make sure there is at least some default config present.
    feed_file = os.path.join(manifest_dir, 'misp_feeds.txt')
    if not os.path.isfile(feed_file):
        with open(feed_file, 'w') as feed_h:
            feed_h.write("https://www.circl.lu/doc/misp/feed-osint/")


def handle_event_file(feed_url: Text, uuid: Text, proxy_string: Optional[Text] = None, cert_file: Optional[Text] = None) -> misp.Event:
    """Download, parse and store single event file"""

    info("Handling {0} from {1}".format(uuid, feed_url))

    proxies: Optional[Dict[Text, Text]] = None

    if proxy_string:
        proxies = {
            'http': proxy_string,
            'https': proxy_string
        }

    url = urlparse.urljoin(feed_url, "{0}.json".format(uuid))
    req = requests.get(url, proxies=proxies, verify=cert_file)
    return misp.Event(loads=req.text)


def handle_feed(manifest_dir: Text,
                feed_url: Text,
                proxy_string: Optional[Text] = None,
                cert_file: Optional[Text] = None) -> Generator[misp.Event, None, None]:
    """Get the manifest file, check if an event file is downloaded
    before (cache) and dispatch event handling of separate files"""

    proxies: Optional[Dict[Text, Text]] = None

    if proxy_string:
        proxies = {
            'http': proxy_string,
            'https': proxy_string
        }

    manifest_url = urlparse.urljoin(feed_url, "manifest.json")
    req = requests.get(manifest_url, proxies=proxies, verify=cert_file)

    manifest = json.loads(req.text)

    feed_sha1 = hashlib.sha1(feed_url.encode("utf-8")).hexdigest()

    try:
        with open(os.path.join(manifest_dir, feed_sha1)) as infile:
            old_manifest = json.load(infile)
    except IOError:
        old_manifest = {}

    for uuid in manifest:
        if uuid not in old_manifest:
            yield handle_event_file(feed_url, uuid, proxy_string, cert_file)

    with open(os.path.join(manifest_dir, feed_sha1), "wb") as outfile:
        outfile.write(json.dumps(manifest).encode("utf-8"))


def main() -> None:
    """program entry point"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    manifest_dir = args.manifest_dir

    actapi = worker.init_act(args)

    verify_manifest_dir(manifest_dir)
    misp_feeds_file = os.path.join(manifest_dir, "misp_feeds.txt")

    with open(misp_feeds_file) as f:
        for line in f:
            feed_data = handle_feed(manifest_dir, line.strip(), args.proxy_string, args.cert_file)
            for event in feed_data:
                n = 0
                e = 0

                act.api.helpers.handle_fact(
                    actapi.fact("hasTitle", event.info)
                    .source("report", str(event.uuid)),
                    output_format=args.output_format)

                n += 1

                try:
                    act.api.helpers.handle_fact(
                        actapi.fact("externalLink")
                        .source("uri", "{0}/{1}.json".format(line.strip(), event.uuid))
                        .destination("report", str(event.uuid)),
                        output_format=args.output_format)

                    n += 1
                except act.api.base.ResponseError as err:
                    e += 1
                    error("Error adding fact to platform", exc_info=True)

                for attribute in event.attributes:
                    if not attribute.act_type:
                        continue
                    try:
                        act.api.helpers.handle_fact(
                            actapi.fact("mentions", attribute.act_type)
                            .source("report", str(event.uuid))
                            .destination(attribute.act_type, attribute.value),
                            output_format=args.output_format)
                        n += 1
                    except act.api.base.ResponseError as err:
                        e += 1
                        error("Error adding fact to platform", exc_info=True)
                info("{0} facts. {1} errors.".format(n, e))


def main_log_error() -> None:
    "Call main() and log all exceptions as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
