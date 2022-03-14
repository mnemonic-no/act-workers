"""Common worker library"""

import argparse
import json
import smtplib
import socket
import sys
import urllib.parse
from email.mime.text import MIMEText
from logging import warning
from typing import Any, Optional

import act.api
import requests
import urllib3
from act.types.format import object_format
from act.types.types import object_validates


class NotAllowed(Exception):
    """UnsupportedScheme is used when parsing URLs that does not contain a supported scheme"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class FetchError(Exception):
    """UnsupportedScheme is used when parsing URLs that does not contain a supported scheme"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class UnsupportedScheme(Exception):
    """UnsupportedScheme is used when parsing URLs that does not contain a supported scheme"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class NoResult(Exception):
    """NoResult is used in API request (no data returned)"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class UnknownFormat(Exception):
    """UnknownFormat is used on unknown parsing formats"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class ResourceLimitExceeded(Exception):
    """Resource Limits Exceeded"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class ServiceTimeout(Exception):
    """Internal service timeouts"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class AuthenticationError(Exception):
    """Authentication Errors"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


def parseargs(description: str) -> argparse.ArgumentParser:
    """Parse arguments"""

    parser = act.api.libs.cli.parseargs(description, fact_arguments=True)

    parser.add_argument(
        "--disabled",
        dest="disabled",
        action="store_true",
        help="Worker is disabled (exit immediately)",
    )
    return parser


def init_act(
    args: argparse.Namespace, no_format: bool = False, no_validate: bool = False
) -> act.api.Act:

    """Initialize act api from arguments"""

    api = act.api.libs.cli.init_act(
        args,
        object_formatter=None if no_format else object_format,
        object_validator=None if no_validate else object_validates,
    )

    # This check is done here to make sure logging is set up
    if args.disabled:
        warning("Worker is disabled")
        sys.exit(0)

    return api


def fetch(
    url: str, proxy_string: Optional[str], timeout: int = 60, verify_https: bool = False
) -> Any:
    """Fetch remote URL and return content
    url (string):                    File or URL to fetch
    proxy_string (string, optional): Optional proxy string on format host:port
    timeout (int, optional):         Timeout value for query (default=60 seconds)
    """

    proxies = {"http": proxy_string, "https": proxy_string}

    options = {
        "verify": verify_https,
        "timeout": timeout,
        "proxies": proxies,
        "params": {},
    }

    parsed = urllib.parse.urlparse(url)

    # No scheme - assume this is a file
    if not parsed.scheme:
        return open(url).read()

    if not parsed.scheme.lower() in ("http", "https"):
        raise UnsupportedScheme(f"Unsupported scheme in {url}")

    if not verify_https:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        req = requests.get(url, **options)
    except (
        urllib3.exceptions.ReadTimeoutError,
        requests.exceptions.ReadTimeout,
        socket.timeout,
    ) as err:
        raise FetchError(
            "Timeout ({0.__class__.__name__}), query: {1}".format(err, url)
        )

    if not req.status_code == 200:
        errmsg = "status_code: {0.status_code}: {0.content}"
        raise FetchError(errmsg.format(req))

    return req.text


def fetch_json(
    url: str, proxy_string: Optional[str], timeout: int = 60, verify_https: bool = False
) -> Any:
    """Fetch remote URL or local and return content parse as json
    url (string):                    File or URL to fetch
    proxy_string (string, optional): Optional proxy string on format host:port
    timeout (int, optional):         Timeout value for query (default=60 seconds)
    """
    content = fetch(url, proxy_string, timeout, verify_https)
    try:
        return json.loads(content)
    except json.decoder.JSONDecodeError as e:
        raise FetchError(f"Cannot parse as json {e}, {content} {url}")


def sendmail(
    smtphost: str, sender: str, recipient: str, subject: str, body: str
) -> None:
    """Send email"""

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    s = smtplib.SMTP(smtphost)
    s.sendmail(sender, [recipient], msg.as_string())
    s.quit()
