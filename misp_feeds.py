#!/usr/bin/env python3
"""MISP feed worker pulling down feeds in misp_feeds.txt
and adding data to the platform"""

import act
import hashlib
import json
import misp
import os
import requests
import sys
import syslog

try:
    import urlparse
except ModuleNotFoundError:  # Python3
    import urllib.parse as urlparse


def log(*msg):
    """log to syslog if running as a daemon/cronjob.
    otherwise log to stdout"""

    mymsg = " ".join(msg)
    if sys.stdin.isatty():
        print(mymsg)
    else:
        syslog.syslog(mymsg)


def verify_dir():
    """Verify that the directory structure exists and that there is
    always a feed file (Even empty)"""

    if not os.path.isdir("misp"):
        os.mkdir("misp")
    if not os.path.isdir("misp/manifest"):
        os.mkdir("misp/manifest")
    if not os.path.isfile("misp/misp_feeds.txt"):
        with open("misp/misp_feeds.txt", "wb"):
            pass


def handle_event_file(feed_url, uuid):
    """Download, parse and store single event file"""

    log("Handling {0} from {1}".format(uuid, feed_url))

    url = urlparse.urljoin(feed_url, "{0}.json".format(uuid))
    req = requests.get(url)
    event = misp.Event(loads=req.text)

    print(event)


def handle_feed(feed_url):
    """Get the manifest file, check if an event file is downloaded
    before (cache) and dispatch event handling of separate files"""

    manifest_url = urlparse.urljoin(feed_url, "manifest.json")
    req = requests.get(manifest_url)

    manifest = json.loads(req.text)

    feed_sha1 = hashlib.sha1(feed_url.encode("utf-8")).hexdigest()

    try:
        with open("misp/manifest/{0}".format(feed_sha1)) as f:
            old_manifest = json.load(f)
    except IOError:
        old_manifest = {}

    for uuid in manifest:
        if uuid not in old_manifest:
            handle_event_file(feed_url, uuid)

    with open("misp/manifest/{0}".format(feed_sha1), "wb") as f:
        f.write(json.dumps(manifest).encode("utf-8"))


def main():
    """program entry point"""

    verify_dir()

    with open("misp/misp_feeds.txt") as f:
        for line in f:
            feed_data = handle_feed(line.strip())
            print(feed_data)


def add_fact(client, source_type, source_values, fact_type, destination_type, destination_values, link_type="linked"):
    """
    Add facts for all combinations of source_values and destination_values,
    using the specified source_type, fact_type, destination_type and
    link_type.

    Args:
        client(act.Act):            ACT instance
        source_type(str):           ACT object source type
        source_values(str[]):       List of source values
        destination_type(str):      ACT object destination type
        destination_values(str[]):  List of destination values
        link_type(str):             linked|bidirectional

    link_type == linked, means a fact with a specified source and destination.
    link_type == bidirectional, means a fact where source/destination have a two way direction

    """

    # Ensure source/destination values lists, if not enclose in a list with a single value
    if isinstance(destination_values, str):
        destination_values = [destination_values]

    if isinstance(source_values, str):
        source_values = [source_values]

    for source_value in source_values:
        try:
            for destination_value in destination_values:
                fact = None
                if source_type == destination_type and source_value == destination_value:
                    continue  # Do not link to itself

                if link_type == "linked":
                    fact = client.fact(fact_type)\
                        .source(source_type, source_value)\
                        .destination(destination_type, destination_value)
                elif link_type == "bidirectional":
                    fact = client.fact(fact_type)\
                        .bidirectional(source_type, source_value)\
                        .bidirectional(destination_type, destination_value)
                else:
                    log("Illegal link_type: %s" % link_type)
                    continue

                if client.act_baseurl:  # Add fact toplatform
                    fact.add()
                else:
                    print(fact.json())  # Print fact to stdout, if baseurl is NOT set

        except act.base.ResponseError as e:
            log(e)
            continue


if __name__ == "__main__":
    main()
