""" Cache hash of content downloaded from URL """

import datetime
import hashlib
import os
import sqlite3
import time
from logging import info
from typing import Dict, NamedTuple, Optional, Text

import caep
import requests

from act.workers.libs import worker


class CacheResponse(NamedTuple):
    """ Response object from cache query """
    status_code: Optional[int]
    report_hash: Optional[Text]
    added: datetime.datetime


class UrlContentHash(NamedTuple):
    """ Response object with status code and sha256 hash """
    status_code: Optional[int]
    sha256: Optional[Text]


CACHE_PREFIX = "act-workers"


def get_db_cache(cache_dir: Text) -> sqlite3.Connection:
    """
    Open cache and return sqlite3 connection
    Table is created if it does not exists
    """
    cache_file = os.path.join(cache_dir, "urlcache.sqlite3")
    conn = sqlite3.connect(cache_file)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS report_hash (
        url string primary key,
        status_code int,
        sha256 string,
        added int)
    """)
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS report_url on report_hash(url)")

    return conn


class URLCache:
    """ Cache hash of content downloaded from URL """

    def __init__(
            self,
            cache_prefix: Text = CACHE_PREFIX,
            requests_common_kwargs: Optional[Dict] = None) -> None:

        self.requests_common_kwargs = \
            requests_common_kwargs if requests_common_kwargs else {}

        cache_dir = caep.get_cache_dir(cache_prefix, create=True)
        self.cache: sqlite3.Connection = get_db_cache(cache_dir)

    def query_cache(self, url: Text) -> CacheResponse:
        """ Query cache for a specific url """
        cursor = self.cache.cursor()

        res = cursor.execute("SELECT * FROM report_hash WHERE url = ?", [url.strip()]).fetchall()

        if not res:
            return CacheResponse(None, None, datetime.datetime.utcfromtimestamp(0))

        return CacheResponse(res[0][1], res[0][2], datetime.datetime.utcfromtimestamp(res[0][3]))

    def update_cache(self, url: Text, status_code: Optional[int], report_hash: Optional[Text]) -> None:
        """ Add url/hash to cache """
        cursor = self.cache.cursor()

        # Check if url exists
        res = cursor.execute("SELECT * FROM report_hash WHERE url = ?", [url.strip()]).fetchall()

        if res:
            info("Update cache {}, {}, {}".format(url, status_code, report_hash))
            cursor.execute(
                "UPDATE report_hash set status_code = ?, sha256 = ?, added = ? where url = ?",
                [status_code, report_hash, int(time.time()), url])
        else:
            info("Insert cache {} -> {}".format(url, report_hash))
            cursor.execute("INSERT INTO report_hash VALUES (?,?,?,?)", [url, status_code, report_hash, time.time()])

        self.cache.commit()

    def url_sha256(self, url: Text) -> UrlContentHash:
        "Retrieve URL and return sha256 of content. Returns None if request fails."

        sha256 = None
        status_code = None

        try:
            req = requests.get(url, **self.requests_common_kwargs)
            status_code = req.status_code
            if req.status_code == 200:
                sha256 = hashlib.sha256(req.content).hexdigest()
            else:
                info("Failed downloading {}: {}".format(url, req.status_code))
        except requests.exceptions.ReadTimeout:
            info("Timeout downloading {}".format(url))
        except Exception as err:  # pylint: disable=broad-except
            info("Unknown exception downloading {}: {}".format(url, err))

        return UrlContentHash(status_code, sha256)

    def query_download_update(self, url: Text) -> Optional[Text]:
        """

        Query cache for url. If not found in url, or cache entry is old, download content

        Returns sha256 of content, or None if unable to download

        """

        cache = self.query_cache(url)

        now = datetime.datetime.now()

        if cache.report_hash and cache.added > now - datetime.timedelta(days=7):
            info("URL in cache (with hash found): {}, {}, {}, {}".format(url, cache.report_hash, cache.status_code, time.time()))
        elif (not cache.report_hash) and (cache.status_code == 404) and (cache.added > now - datetime.timedelta(days=7)):
            info("URL in cache (last status was 404): {}, {}, {}, {}".format(url, cache.report_hash, cache.status_code, time.time()))
        elif (not cache.report_hash) and (cache.added > now - datetime.timedelta(days=2)):
            # status_code != 404 - attempt new download
            info("URL in cache (Unknown status): {}, {}, {}, {}".format(url, cache.report_hash, cache.status_code, time.time()))
        else:
            query = self.url_sha256(url)
            self.update_cache(url, query.status_code, query.sha256)
            return query.sha256

        return cache.report_hash
