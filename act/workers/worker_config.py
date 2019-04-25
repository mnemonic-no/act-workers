#!/usr/bin/env python3
""" Handle worker config"""

import argparse
import os
import sys
from typing import Text

from pkg_resources import resource_string

from act.workers.libs import config, worker


def parseargs() -> argparse.Namespace:
    """ Parse arguments """

    parser = argparse.ArgumentParser("ACT worker config", epilog="""
    show - Print default config

    user - Copy default config to {0}/{1}

    system - Copy default config to /etc/{1}

""".format(config.get_config_dir(worker.CONFIG_ID), worker.CONFIG_NAME), formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('action', nargs=1, choices=["show", "user", "system"])

    return parser.parse_args()


def default_ini() -> Text:
    "Get content of default ini file"
    return resource_string("act.workers", "etc/{}".format(worker.CONFIG_NAME)).decode('utf-8')


def save_config(filename: Text) -> None:
    """ Save config to specified filename """
    if os.path.isfile(filename):
        sys.stderr.write("Config already exists: {}\n".format(filename))
        sys.exit(1)

    try:
        with open(filename, "w") as f:
            f.write(default_ini())
    except PermissionError as err:
        sys.stderr.write("{}\n".format(err))
        sys.exit(2)

    print("Config copied to {}".format(filename))


def main() -> None:
    "main function"
    args = parseargs()

    if "show" in args.action:
        print(default_ini())

    if "user" in args.action:
        config_dir = config.get_config_dir(worker.CONFIG_ID, create=True)
        save_config(os.path.join(config_dir, worker.CONFIG_NAME))

    if "system" in args.action:
        save_config("/etc/{}".format(worker.CONFIG_NAME))


if __name__ == '__main__':
    main()
