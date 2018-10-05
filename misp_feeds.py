#!/usr/bin/env python3.6
"""MISP feed worker pulling down feeds in misp_feeds.txt
and adding data to the platform"""

import act
import argparse
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
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True, help='API URI')
    parser.add_argument("--logfile", dest="logfile", help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")
    parser.add_argument('--proxy', metavar='PROXY', type=str,
                        help='set the system proxy')
    parser.add_argument('--cert', metavar="CERTFILE", type=str,
                        help='Read certificate from file (ie. self signed proxy)')

    return parser.parse_args()


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

    if ARGS.loglevel == "info":
        log("Handling {0} from {1}".format(uuid, feed_url))

    if ARGS.proxy:
        proxies = {
            'http': ARGS.proxy,
            'https': ARGS.proxy,
        }
    else:
        proxies = None

    if ARGS.cert:
        certfile = ARGS.cert
    else:
        certfile = None

    url = urlparse.urljoin(feed_url, "{0}.json".format(uuid))
    req = requests.get(url, proxies=proxies, verify=certfile)
    return misp.Event(loads=req.text)


def handle_feed(feed_url):
    """Get the manifest file, check if an event file is downloaded
    before (cache) and dispatch event handling of separate files"""

    if ARGS.proxy:
        proxies = {
            'http': ARGS.proxy,
            'https': ARGS.proxy,
        }
    else:
        proxies = None

    if ARGS.cert:
        certfile = ARGS.cert
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


def main(client):
    """program entry point"""

    verify_dir()

    with open("misp/misp_feeds.txt") as f:
        for line in f:
            feed_data = handle_feed(line.strip())
            for event in feed_data:
                n = 0
                e = 0
                if not ARGS.act_baseurl:
                    print(Style.BRIGHT, Fore.BLUE, event.info, Style.RESET_ALL)

                fact = actapi.fact("hasTitle", event.info)\
                             .source("report", str(event.uuid))
                if ARGS.act_baseurl:
                    fact.add()
                    n += 1
                else:
                    print(Style.BRIGHT, Fore.YELLOW, fact.json(), Style.RESET_ALL)

                fact = actapi.fact("externalLink")\
                             .source("uri", "{0}/{1}.json".format(line.strip(), event.uuid))\
                             .destination("report", str(event.uuid))
                if ARGS.act_baseurl:
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
                    if ARGS.act_baseurl:
                        try:
                            fact.add()
                            n += 1
                        except act.base.ResponseError as err:
                            e += 1
                            log(str(err))
                    else:
                        print(Style.BRIGHT, Fore.YELLOW, fact.json(), Style.RESET_ALL)
                log("Added {0} facts. {1} errors.".format(n, e))


if __name__ == "__main__":
    ARGS = parseargs()

    actapi = act.Act(ARGS.act_baseurl, ARGS.act_user_id, ARGS.loglevel, ARGS.logfile, "misp-import")
    main(actapi)
