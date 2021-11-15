#!/usr/bin/env python3.6
"""

act feed worker pulling down fact bundles and either:
- dumping to directory
or
- upload to platform

"""

import argparse
import gzip
import hashlib
import io
import os
import traceback
import urllib.parse as urlparse
from logging import error, info, warning
from pathlib import Path
from typing import Dict, Optional, Text

import act.api
import act.api.helpers
import caep
import pid
import requests
from act.api.libs import cli

from act.workers.generic_uploader import uploader
from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """Parse arguments"""
    parser = worker.parseargs("Get act feeds from act sharing directories")

    parser.add_argument(
        "--feed-uri",
        help="URI to retrieve feed from",
    )

    parser.add_argument(
        "--dump-dir",
        type=Path,
        help="Dump manifest/bundles to directory instead of sendings facts to uploader",
    )

    parser.add_argument(
        "--feed-cache",
        type=Path,
        default=caep.get_cache_dir("act_feed_cache"),
        help="The directory to store information about last run",
    )

    parser.add_argument(
        "--no-exit-on-error",
        action="store_true",
        help="Log errors and continue on platform upload errors",
    )

    return parser


def get_last_run_filename(feed_cache: Path, feed_uri: Text) -> Path:
    """Use hash of feed as cache file, so you can run multiple processes with feed"""
    if str(feed_cache) == caep.get_cache_dir("act_feed_cache"):
        caep.get_cache_dir("act_feed_cache", create=True)

    return feed_cache / Path(hashlib.sha256(feed_uri.encode()).hexdigest())


def get_last_run(last_run_file: Path) -> int:
    """Get last run"""

    if not last_run_file.is_file():
        warning("Last run file not found, assuming first run")
        return 0

    with open(last_run_file) as f:
        return int(f.read())


def update_last_run(last_run_file: Path, last_run: int) -> None:
    """Update last run file"""

    with open(last_run_file, "w") as f:
        f.write(str(last_run))


def handle_bundle(
    feed_uri: Text,
    bundle: Text,
    actapi: act.api.Act,
    dump_dir: Path,
    proxies: Optional[Dict[Text, Text]] = None,
    cert_file: Optional[Text] = None,
    no_exit_on_error: bool = False,
) -> None:
    """Retrieve and handle bundle file"""

    bundle_uri = urlparse.urljoin(feed_uri, bundle)

    req = requests.get(bundle_uri, proxies=proxies, verify=cert_file)

    if dump_dir:
        info("Storing to %s, %s", dump_dir, bundle_uri)
        with open(dump_dir / Path(bundle), "wb") as f:
            f.write(req.content)

    else:
        info("Iterate over facts in uploader: %s", bundle_uri)

        # uploader will print facts to stdout unless act_baseurl is set
        with gzip.open(io.BytesIO(req.content), "rb") as facts:
            uploader(actapi, facts, no_exit_on_error=no_exit_on_error)


def handle_feed(
    last_run_filename: Path,
    feed_uri: Text,
    actapi: act.api.Act,
    dump_dir: Path,
    proxies: Optional[Dict[Text, Text]] = None,
    cert_file: Optional[Text] = None,
    no_exit_on_error: bool = False,
) -> int:
    """Get the manifest file, and handle new bundles"""

    last_run = get_last_run(last_run_filename)

    # Ensure URI ends with "/" so it can be joined with manifests/bundles
    if not feed_uri.endswith("/"):
        feed_uri += "/"

    manifest_uri = urlparse.urljoin(feed_uri, "manifest.json")
    req = requests.get(manifest_uri, proxies=proxies, verify=cert_file)

    manifest = req.json()

    if dump_dir:
        with open(dump_dir / Path("manifest.json"), "w") as f:
            f.write(req.text)

    # for each bundle handled, the update time will be stored to disk
    # so it needs to be sorted by update time
    manifests = sorted(manifest["bundles"].items(), key=lambda item: item[1])

    for bundle, updated in manifests:
        # Skip if the file is modified *before* last run
        if updated <= last_run:
            info(
                "Skipping bundle %s, updated %s, last_run=%s", bundle, updated, last_run
            )
            continue

        handle_bundle(
            feed_uri,
            bundle,
            actapi,
            dump_dir,
            proxies,
            cert_file,
            no_exit_on_error,
        )

        # update last run after sucessfull handling of bundle file
        update_last_run(last_run_filename, updated)


def main() -> None:
    """program entry point"""

    # Look for default ini file in "/etc/actworkers.ini" and
    # ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = cli.handle_args(parseargs())

    if not args.feed_uri:
        cli.fatal("--feed-uri not specified")

    if args.dump_dir and not args.dump_dir.is_dir():
        os.makedirs(args.dump_dir)

    proxies = (
        {"http": args.proxy_string, "https": args.proxy_string}
        if args.proxy_string
        else None
    )

    actapi = worker.init_act(args)

    try:
        # Get "updated" from last successful run
        last_run_filename = get_last_run_filename(args.feed_cache, args.feed_uri)

        with pid.PidFile(force_tmpdir=True, pidname="act_feed.pid"):
            handle_feed(
                last_run_filename,
                args.feed_uri,
                actapi,
                args.dump_dir,
                proxies,
                args.cert_file,
                args.no_exit_on_error,
            )

    except pid.base.PidFileAlreadyLockedError:
        error("pid file found - feed is already running")


def main_log_error() -> None:
    "Call main() and log all exceptions as errors"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
