#!/usr/bin/env python3

"""ip filter plugin


Copyright 2020 mnemonic AS <opensource@mnemonic.no>

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

echo the first line and return exit status based on IP type:

Filter out all lines if parsed as IP address and IP is

- Multicast (RFC 3171, RFC 2373)
- Private (RC 1918, RFC 4193)
- Unspecified (RFC 5735, RFC 2373)
- Reserved (IETF)
- Loopback (RF C3330, RFC 2372)
- Link local (RF3927)

"""


import ipaddress
import sys
import traceback
from logging import debug, error

from act.workers.libs import worker


def process() -> None:
    """Read ip addresses from stdin"""

    output_rows = 0

    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            # No IP Address
            print(line)
            output_rows += 1
            continue

        if ip.is_multicast:
            #  reserved for multicast use. See RFC 3171 (for IPv4) or RFC 2373 (for IPv6).
            continue

        if ip.is_private:
            # private networks. See RFC 1918 (for IPv4) or RFC 4193 (for IPv6).
            continue

        if ip.is_unspecified:
            # unspecified. See RFC 5735 (for IPv4) or RFC 2373 (for IPv6).
            continue

        if ip.is_reserved:
            # IETF reserved.
            continue

        if ip.is_loopback:
            # loopback address. See RFC 3330 (for IPv4) or RFC 2373 (for IPv6).
            continue

        if ip.is_link_local:
            # link-local usage. See RFC 3927.
            continue

        print(line)
        output_rows += 1

    if not output_rows:
        debug("All rows are filtered out")


def main() -> None:
    """Main function"""
    args = worker.handle_args(worker.parseargs("IP Filter"))
    worker.init_act(args)
    process()


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
