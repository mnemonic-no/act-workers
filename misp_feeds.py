#!/usr/bin/env python3.6
"""MISP feed worker pulling down feeds in misp_feeds.txt
and adding data to the platform"""

import act
from logging import error
import traceback
import argparse
import configparser
import collections
import hashlib
import json
import misp
import os
import requests
import sys
import syslog

from colorama import Fore, Style

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


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='Get SCIO reports and IOCs from stdin')
    parser.add_argument('--userid', dest='act_user_id', required=True, help="User ID")
    parser.add_argument('--config', metavar="CONFIGFILE", default="/etc/actworkers.ini", type=str,
                        help='Use this file for config.')

    return parser.parse_args()


def verify_dir():
    """Verify that the directory structure exists and that there is
    always a feed file (Even empty)"""

    if not os.path.isdir(CONF['misp']['manifest_dir']):
        print("Could not open manifest directory:", CONF['misp']['manifest_dir'])
    feed_file = os.path.join(CONF['misp']['manifest_dir'], 'misp_feeds.txt')
    if not os.path.isfile(feed_file):
        with open(feed_file, "wb"):
            pass


def handle_event_file(feed_url, uuid):
    """Download, parse and store single event file"""

    if CONF['misp']['loglevel'] == "info":
        log("Handling {0} from {1}".format(uuid, feed_url))

    if CONF['proxy']['host']:
        proxies = {
            'http': "{}:{}".format(CONF['proxy']['host'], CONF['proxy']['port']),
            'https': "{}:{}".format(CONF['proxy']['host'], CONF['proxy']['port']),
        }
    else:
        proxies = None

    if CONF['cert']['file']:
        certfile = CONF['cert']['file']
    else:
        certfile = None

    url = urlparse.urljoin(feed_url, "{0}.json".format(uuid))
    req = requests.get(url, proxies=proxies, verify=certfile)
    return misp.Event(loads=req.text)


def handle_feed(feed_url):
    """Get the manifest file, check if an event file is downloaded
    before (cache) and dispatch event handling of separate files"""

    if CONF['proxy']['host']:
        proxies = {
            'http': "{}:{}".format(CONF['proxy']['host'], CONF['proxy']['port']),
            'https': "{}:{}".format(CONF['proxy']['host'], CONF['proxy']['port']),
        }
    else:
        proxies = None

    if CONF['cert']['file']:
        certfile = CONF['cert']['file']
    else:
        certfile = None

    manifest_url = urlparse.urljoin(feed_url, "manifest.json")
    req = requests.get(manifest_url, proxies=proxies, verify=certfile)

    manifest = json.loads(req.text)

    feed_sha1 = hashlib.sha1(feed_url.encode("utf-8")).hexdigest()

    try:
        with open("misp/manifest/{0}".format(feed_sha1)) as f:
            old_manifest = json.load(f)
    except IOError:
        old_manifest = {}

    for uuid in manifest:
        if uuid not in old_manifest:
            yield handle_event_file(feed_url, uuid)

    with open("misp/manifest/{0}".format(feed_sha1), "wb") as f:
        f.write(json.dumps(manifest).encode("utf-8"))


def enrich(act_type, value, status=collections.defaultdict(int)):
    url = CONF['misp_enrich'].get(act_type, None)

    if url:
        status[act_type] += 1
        requests.post(url, data=value)
    return status.copy()


def main(client):
    """program entry point"""

    verify_dir()
    status = {}  # in case of empty feed/no enrichment uploads.

    with open("misp/misp_feeds.txt") as f:
        for line in f:
            feed_data = handle_feed(line.strip())
            for event in feed_data:
                n = 0
                e = 0
                if not CONF['platform']['base_url']:
                    print(Style.BRIGHT, Fore.BLUE, event.info, Style.RESET_ALL)

                fact = actapi.fact("hasTitle", event.info)\
                             .source("report", str(event.uuid))
                if CONF['platform']['base_url']:
                    fact.add()
                    n += 1
                else:
                    print(Style.BRIGHT, Fore.YELLOW, fact.json(), Style.RESET_ALL)

                fact = actapi.fact("externalLink")\
                             .source("uri", "{0}/{1}.json".format(line.strip(), event.uuid))\
                             .destination("report", str(event.uuid))
                if CONF['platform']['base_url']:
                    try:
                        fact.add()
                        n += 1
                    except act.base.ResponseError as err:
                        e += 1
                        log(str(err))
                else:
                    print(Style.BRIGHT, Fore.YELLOW, fact.json(), Style.RESET_ALL)

                for attribute in event.attributes:
                    if not attribute.act_type:
                        continue
                    fact = actapi.fact("seenIn", "report")\
                                 .source(attribute.act_type, attribute.value)\
                                 .destination("report", str(event.uuid))
                    status = enrich(attribute.act_type, attribute.value)
                    if CONF['platform']['base_url']:
                        try:
                            fact.add()
                            n += 1
                        except act.base.ResponseError as err:
                            e += 1
                            log(str(err))
                    else:
                        print(Style.BRIGHT, Fore.YELLOW, fact.json(), Style.RESET_ALL)
                log("Added {0} facts. {1} errors.".format(n, e))
        for k, v in status.items():
            log("{} {} sent to enrichment".format(v, k))


if __name__ == "__main__":
    ARGS = parseargs()
    CONF = configparser.ConfigParser()
    read = CONF.read(ARGS.config)
    if len(read) == 0:
        print("Could not read config file")
        sys.exit(1)

    try:
        actapi = act.Act(CONF['platform']['base_url'],
                         ARGS.act_user_id,
                         CONF['misp']['loglevel'],
                         CONF['misp']['logfile'],
                         "misp-import")
        main(actapi)
    except Exception as e:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise
