"""Common worker library"""

import argparse
import smtplib
import socket
from email.mime.text import MIMEText
from logging import error
from typing import Optional, Any

import requests
import urllib3

import act


class UnknownResult(Exception):
    """UnknownResult is used in API request (not 200 result)"""

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
    return parser


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


def handle_fact(fact: act.fact.Fact) -> None:
    """ add fact if we configured act_baseurl - if not print fact """
    if fact.config.act_baseurl:
        fact.add()
    else:
        print(fact)


def sendmail(smtphost: str, sender: str, recipient: str, subject: str, body: str) -> None:
    """Send email"""

    msg = MIMEText(body, "plain", "utf-8")
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient
    s = smtplib.SMTP(smtphost)
    s.sendmail(sender, [recipient], msg.as_string())
    s.quit()
