"""Common worker library"""

import argparse
import inspect
import os
import smtplib
import socket
import sys
from email.mime.text import MIMEText
from logging import error, warning
from typing import Any, Optional, Text

import requests
import urllib3

import act.api
from act.workers.libs import config

CONFIG_ID = "actworkers"
CONFIG_NAME = "actworkers.ini"


class UnknownResult(Exception):
    """UnknownResult is used in API request (not 200 result)"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


def parseargs(description: str) -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="{} ({})".format(description, worker_name()), epilog="""

  --config INI_FILE     Override default locations of ini file

    Arguments can be specified in ini-files, environment variables and
    as command line arguments, and will be parsed in that order.

    By default, workers will look for an ini file in /etc/{1}
    and ~/.config/{0}/{1} (or in $XDG_CONFIG_DIR if
    specified).

    Each worker will read the confiuration from the "DEFAULT" section in the
    ini file, and in it's own section (in that order).

    It is also possible to use environment variables for configuration.
    Workers will look for environment variables for all arguments with
    the argument name in uppercase and "-" replaced with "_".

    E.g. set the CERT_FILE environment variable to configure the
    --cert-file option.

""".format(CONFIG_ID, CONFIG_NAME), formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--http-timeout', dest='http_timeout', type=int,
                        default=120, help="Timeout")
    parser.add_argument('--proxy-string', dest='proxy_string', help="Proxy to use for external queries")
    parser.add_argument('--cert-file', dest='cert_file', help="Cerfiticate to add if you are behind a SSL/TLS interception proxy.")
    parser.add_argument('--user-id', dest='user_id',
                        help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl',
                        help='ACT API URI')
    parser.add_argument("--logfile", dest="logfile",
                        help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")
    parser.add_argument("--output-format", dest="output_format", choices=["str", "json"], default="json",
                        help="Output format for fact (default=json)")
    parser.add_argument('--http-user', dest='http_user', help="ACT HTTP Basic Auth user")
    parser.add_argument('--http-password', dest='http_password', help="ACT HTTP Basic Auth password")
    parser.add_argument('--disabled', dest='disabled', action="store_true", help="Worker is disabled (exit immediately)")
    return parser


def __mod_name(stack: inspect.FrameInfo) -> Text:
    """ Return name of module from a stack ("_" is replaced by "-") """
    mod = inspect.getmodule(stack[0])
    return os.path.basename(mod.__file__).replace(".py", "").replace("_", "-")


def worker_name() -> Text:
    """ Return first external module that called this function, directly, or indirectly """

    modules = [__mod_name(stack) for stack in inspect.stack() if __mod_name(stack)]
    return [name for name in modules if name != modules[0]][0]


def handle_args(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """ Wrapper for config.handle_args where we set config_id and config_name """
    return config.handle_args(parser, CONFIG_ID, CONFIG_NAME, worker_name())


def init_act(args: argparse.Namespace) -> act.api.Act:
    """ Initialize act api from arguments """
    requests_kwargs = {}
    if args.http_user:
        requests_kwargs["auth"] = (args.http_user, args.http_password)

    if args.cert_file:
        requests_kwargs["verify"] = args.cert_file

    api = act.api.Act(
        args.act_baseurl,
        args.user_id,
        args.loglevel,
        args.logfile,
        worker_name(),
        requests_common_kwargs=requests_kwargs)

    # This check is done here to make sure logging is set up
    if args.disabled:
        warning("Worker is disabled")
        sys.exit(0)

    return api


def get_cache_dir(cache_id: str, create: bool = False) -> str:
    """
    Get cache dir.

    Honors $XDG_CACHE_HOME, but fallbacks to $HOME/.cache

Args:
    cache_id [str]: directory under CACHE that will be used
    create [bool]: create directory if not exists

Return path to cache_directory
    """

    home = os.environ["HOME"]

    cache_home = os.environ.get("XDG_CACHE_HOME", os.path.join(home, ".cache"))
    cache_dir = os.path.join(cache_home, cache_id)

    if create and not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    return cache_dir


def fatal(message: Text, exit_code: int = 1) -> None:
    "Send error to error() and stderr() and exit with exit_code"
    sys.stderr.write(message.strip() + "\n")
    error(message.strip())
    sys.exit(exit_code)


def fetch_json(url: str, proxy_string: Optional[str], timeout: int = 60, verify_https: bool = False) -> Any:
    """Fetch remote URL as JSON
    url (string):                    URL to fetch
    proxy_string (string, optional): Optional proxy string on format host:port
    timeout (int, optional):         Timeout value for query (default=60 seconds)
    """

    proxies = {
        'http': proxy_string,
        'https': proxy_string
    }

    options = {
        "verify": verify_https,
        "timeout": timeout,
        "proxies": proxies,
        "params": {}
    }

    if not verify_https:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        req = requests.get(url, **options)
    except (urllib3.exceptions.ReadTimeoutError,
            requests.exceptions.ReadTimeout,
            socket.timeout) as err:
        error("Timeout ({0.__class__.__name__}), query: {1}".format(err, req.url))

    if not req.status_code == 200:
        errmsg = "status_code: {0.status_code}: {0.content}"
        raise UnknownResult(errmsg.format(req))

    return req.json()


def sendmail(smtphost: str, sender: str, recipient: str, subject: str, body: str) -> None:
    """Send email"""

    msg = MIMEText(body, "plain", "utf-8")
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient
    s = smtplib.SMTP(smtphost)
    s.sendmail(sender, [recipient], msg.as_string())
    s.quit()
