#!/usr/bin/env python3

"""[WORKERNAME] worker for the ACT platform

Copyright YEAR YOU <YOU.YOU2@YOUR.EMAIL>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""


import sys
import traceback
from logging import error
from typing import Text

import act.api
from act.api.libs import cli

import act
from act.workers.libs import worker

WORKER_NAME = "TODO"


def process(api: act.api.Act, output_format: Text = "json") -> None:
    """Read queries from stdin"""

    for query in sys.stdin:
        query = query.strip()

        if not query:
            continue

        # INSERT PROCESSOR CODE HERE
        #
        # https://github.com/mnemonic-no/act-api-python/blob/master/README.md
        #
        # consider using helpers from act.api.helpers such as handle_fact etc.
        #
        # several workers are available under https://github.com/mnemonic-no/act-workers/tree/master/act/workers


def main() -> None:
    """Main function"""
    # Look for default ini file in "/etc/actworkers.ini" and
    # ~/config/actworkers/actworkers.ini (or replace .config with
    # $XDG_CONFIG_DIR if set)
    args = cli.handle_args(worker.parseargs(WORKER_NAME))
    actapi = worker.init_act(args)

    process(actapi, args.output_format)


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == "__main__":
    main_log_error()
