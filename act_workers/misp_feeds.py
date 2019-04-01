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
from act_workers_libs import misp
import os
import requests
import sys
import syslog

from typing import Text, Optional, Dict, Generator
from colorama import Fore, Style

try:
    import urlparse
except ModuleNotFoundError:  # Python3
    import urllib.parse as urlparse  # type: ignore


def log(*msg) -> None:  # type: ignore
    """log to syslog if running as a daemon/cronjob.
    otherwise log to stdout"""

    mymsg = " ".join(msg)
    if sys.stdin.isatty():
        print(mymsg)
    else:
        syslog.syslog(mymsg)


def parseargs() -> argparse.Namespace:
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='Get SCIO reports and IOCs from stdin')
    parser.add_argument('--userid', dest='act_user_id', required=True, help="User ID")
    parser.add_argument('--config', metavar="CONFIGFILE", default="/etc/actworkers.ini", type=str,
                        help='Use this file for config.')

    return parser.parse_args()


def verify_dir(conf: configparser.ConfigParser) -> None:
    """Verify that the directory structure exists and that there is
    always a feed file (Even empty)"""

    if not os.path.isdir(conf['misp']['manifest_dir']):
        print("Could not open manifest directory:", conf['misp']['manifest_dir'])
    feed_file = os.path.join(conf['misp']['manifest_dir'], 'misp_feeds.txt')
    if not os.path.isfile(feed_file):
        with open(feed_file, "wb"):
            pass


def handle_event_file(conf: configparser.ConfigParser, feed_url: Text, uuid: Text) -> misp.Event:
    """Download, parse and store single event file"""

    if conf['misp']['loglevel'] == "info":
        log("Handling {0} from {1}".format(uuid, feed_url))


    proxies: Optional[Dict[Text, Text]] = None

    if conf['proxy']['host']:
        proxies = {
            'http': "{}:{}".format(conf['proxy']['host'], conf['proxy']['port']),
            'https': "{}:{}".format(conf['proxy']['host'], conf['proxy']['port']),
        }

    certfile: Optional[Text] = None

    if conf['cert']['file']:
        certfile = conf['cert']['file']

    url = urlparse.urljoin(feed_url, "{0}.json".format(uuid))
    req = requests.get(url, proxies=proxies, verify=certfile)
    return misp.Event(loads=req.text)


def handle_feed(conf: configparser.ConfigParser, feed_url: Text) -> Generator[misp.Event, None, None]:
    """Get the manifest file, check if an event file is downloaded
    before (cache) and dispatch event handling of separate files"""

    proxies: Optional[Dict[Text, Text]] = None

    if conf['proxy']['host']:
        proxies = {
            'http': "{}:{}".format(conf['proxy']['host'], conf['proxy']['port']),
            'https': "{}:{}".format(conf['proxy']['host'], conf['proxy']['port']),
        }

    certfile: Optional[Text] = None
    if conf['cert']['file']:
        certfile = conf['cert']['file']

    manifest_url = urlparse.urljoin(feed_url, "manifest.json")
    req = requests.get(manifest_url, proxies=proxies, verify=certfile)

    manifest = json.loads(req.text)

    feed_sha1 = hashlib.sha1(feed_url.encode("utf-8")).hexdigest()

    try:
        with open("misp/manifest/{0}".format(feed_sha1)) as infile:
            old_manifest = json.load(infile)
    except IOError:
        old_manifest = {}

    for uuid in manifest:
        if uuid not in old_manifest:
            yield handle_event_file(conf, feed_url, uuid)

    with open("misp/manifest/{0}".format(feed_sha1), "wb") as outfile:
        outfile.write(json.dumps(manifest).encode("utf-8"))


def enrich(conf: configparser.ConfigParser, act_type: Text, value: Text, status: Dict[Text, int] =collections.defaultdict(int)) -> Dict[Text, int]:
    """Post an indicator to a predifined url for enrichment"""

    url = conf['misp_enrich'].get(act_type, None)

    if url:
        status[act_type] += 1
        requests.post(url, data=value)
    return status.copy()


def main() -> None:
    """program entry point"""

    args = parseargs()
    conf = configparser.ConfigParser()
    read = conf.read(args.config)
    if len(read) == 0:
        print("Could not read config file")
        sys.exit(1)

    actapi = act.Act(conf['platform']['base_url'],
                     args.act_user_id,
                     conf['misp']['loglevel'],
                     conf['misp']['logfile'],
                     "misp-import")

    verify_dir(conf)
    status: Dict[Text, int] = {}  # in case of empty feed/no enrichment uploads.

    with open("misp/misp_feeds.txt") as f:
        for line in f:
            feed_data = handle_feed(conf, line.strip())
            for event in feed_data:
                n = 0
                e = 0
                if not conf['platform']['base_url']:
                    print(Style.BRIGHT, Fore.BLUE, event.info, Style.RESET_ALL)

                fact = actapi.fact("hasTitle", event.info)\
                             .source("report", str(event.uuid))
                if conf['platform']['base_url']:
                    fact.add()
                    n += 1
                else:
                    print(Style.BRIGHT, Fore.YELLOW, fact.json(), Style.RESET_ALL)

                fact = actapi.fact("externalLink")\
                             .source("uri", "{0}/{1}.json".format(line.strip(), event.uuid))\
                             .destination("report", str(event.uuid))
                if conf['platform']['base_url']:
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
                    if attribute.value:
                        status = enrich(conf, attribute.act_type, attribute.value)
                    if conf['platform']['base_url']:
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


def main_log_error() -> None:
    "Call main() and log all excetions  as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
