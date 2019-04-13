"""Common worker library"""

import argparse
import configparser
import os
import smtplib
import socket
import sys
from email.mime.text import MIMEText
from logging import error
from typing import Any, List, Optional, Text, cast

import requests
import urllib3
from pkg_resources import resource_string


class UnknownResult(Exception):
    """UnknownResult is used in API request (not 200 result)"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class ConfigNotFound(Exception):
    """Config file not found"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


def parseargs(description: str) -> argparse.ArgumentParser:
    """ Parse arguments """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--http-timeout', dest='timeout', type=int,
                        default=120, help="Timeout")
    parser.add_argument('--proxy-string', dest='proxy_string', help="Proxy to use for external queries")
    parser.add_argument('--userid', dest='user_id',
                        help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl',
                        help='ACT API URI')
    parser.add_argument("--logfile", dest="logfile",
                        help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="loglevel", default="info",
                        help="Loglevel (default = info)")
    parser.add_argument("--output-format", dest="output_format", default="json",
                        help="Output format for fact (default = json)")
    return parser


def get_xdg_dir(xdg_id: str, env_name: Text, default: Text, create: bool = False) -> str:
    """
    Get xdg dir.

    https://specifications.freedesktop.org/basedir-spec/basedir-spe c-0.6.html

    Honors $XDG_*_HOME, but fallbacks to defaults

Args:
    xdg_id [str]: directory under directory that will be used
    env_name [str]: XDG environment variable, e.g. XDG_CACHE_HOME
    env_name [str]: default directory in home directory, e.g. .cache
    create [bool]: create directory if not exists

Return path to cache_directory
    """

    home = os.environ["HOME"]

    xdg_home = os.environ.get(env_name, os.path.join(home, default))
    xdg_dir = os.path.join(xdg_home, xdg_id)

    if create and not os.path.isdir(xdg_dir):
        os.makedirs(xdg_dir)

    return xdg_dir


def get_cache_dir(cache_id: str, create: bool = False) -> str:
    """
    Get cache dir.

    Honors $XDG_CACHE_HOME, but fallbacks to ".cache"

    See get_xdg_dir for details
    """

    return get_xdg_dir(cache_id, "XDG_CACHE_HOME", ".cache", create)


def get_config_dir(config_id: str, create: bool = False) -> str:
    """
    Get config dir.

    Honors $XDG_CONFIG_HOME, but fallbacks to ".config"

    See get_xdg_dir for details
    """

    return get_xdg_dir(config_id, "XDG_CONFIG_HOME", ".config", create)


def get_data_dir(data_id: str, create: bool = False) -> str:
    """
    Get data dir.

    Honors $XDG_DATA_HOME, but fallbacks to ".local/share"

    See get_xdg_dir for details
    """

    return get_xdg_dir(data_id, "XDG_DATA_HOME", ".local/share", create)


def get_ini(ini_id: Text = "actworkers", ini_filename: Text = "actworkers.ini") -> Optional[Text]:
    """
    Look for default ini files in /etc and ~/.config
    """

    # Order to search for confiuration files
    locations: List[Text] = [
        "/etc/{}".format(ini_filename),
        os.path.join(get_config_dir(ini_id), ini_filename)
    ]

    ini_files: List[Text] = [loc for loc in locations if os.path.isfile(loc)]

    if not ini_files:
        raise ConfigNotFound("No ini file found in any of these locations: {}".format(", ".join(locations)))

    # Return first configuration file that exists
    return ini_files[0]


def default_ini() -> Text:
    "Return ini file"

    # Do not use os.path, or relative paths
    # https://setuptools.readthedocs.io/en/latest/pkg_resources.html#basic-resource-access
    return resource_string("act.workers", "etc/actworkers.ini").decode('utf-8')


def get_config(config_filename: Optional[Text]) -> configparser.ConfigParser:
    """ Read config file """

    conf = configparser.ConfigParser()

    if not config_filename:
        try:
            config_filename = get_ini()
        except ConfigNotFound as err:
            sys.stderr.write(str(err))
            sys.stderr.write("\nUse --config-default to print a default configuration file")
            sys.exit(1)

    read = conf.read(cast(Text, config_filename))
    if len(read) == 0:
        print("Could not read config file")
        sys.exit(1)

    return conf


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
