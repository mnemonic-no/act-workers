""" Tests for stix library """

import pytest
from stix2patterns.exceptions import ParseException

from act.workers.libs.stix import (MultipleComparisons, TypesNotString,
                                   single_stix_equal_pattern)


def test_stix_pattern_ok() -> None:
    """test strix patterns that should not fail"""

    assert single_stix_equal_pattern("[file:name = 'shell.aspx']") == (
        "file:name",
        "shell.aspx",
    )

    assert single_stix_equal_pattern("[ipv4-addr:value = '165.232.154.116']") == (
        "ipv4-addr:value",
        "165.232.154.116",
    )

    assert single_stix_equal_pattern(
        "[file:hashes.'SHA-256' = '65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5']"
    ) == (
        "file:hashes.SHA-256",
        "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5",
    )

    assert single_stix_equal_pattern("[domain-name:value = 'sampwn.anondns.net']") == (
        "domain-name:value",
        "sampwn.anondns.net",
    )

    assert single_stix_equal_pattern("[url:value = 'https://teamtnt.red']") == (
        "url:value",
        "https://teamtnt.red",
    )

    assert single_stix_equal_pattern("[email-addr:value = 'admin@abcovid.tech']") == (
        "email-addr:value",
        "admin@abcovid.tech",
    )

    # stix2pattern is uanble to parse this
    # assert single_stix_equal_pattern(
    #     "[windows-registry-key:key = 'HKEY_CURRENT_USER\\Console\\QuickEdit']"
    # ) == (
    #     "windows-registry-key:key",
    #     "HKEY_CURRENT_USER\\Console\\QuickEdit",
    # )

    assert single_stix_equal_pattern(
        "[process:command_line = 'vssadmin resize shadowstorage /for=h: /on=h: /maxsize=unbounded']"
    ) == (
        "process:command_line",
        "vssadmin resize shadowstorage /for=h: /on=h: /maxsize=unbounded",
    )

    # stix2pattern is uanble to parse this
    # assert single_stix_equal_pattern("[mutex:name = 'Global\\EKANS']") == (
    #     "mutex:name",
    #     "Global\\EKANS",
    # )

    assert single_stix_equal_pattern(
        "[x509-certificate:issuer = 'CN=antivirus.comodo.com']"
    ) == ("x509-certificate:issuer", "CN=antivirus.comodo.com")

    assert single_stix_equal_pattern("[software:name = 'Spelevo Exploit Kit']") == (
        "software:name",
        "Spelevo Exploit Kit",
    )

    assert single_stix_equal_pattern(
        "[file:hashes.'MD5' = '0011fb4f42ee9d68c0f2dc62562f53e0']"
    ) == (
        "file:hashes.MD5",
        "0011fb4f42ee9d68c0f2dc62562f53e0",
    )

    assert single_stix_equal_pattern("[email-message:subject = 'Request Help']") == (
        "email-message:subject",
        "Request Help",
    )

    assert single_stix_equal_pattern(
        "[network-traffic:extensions.'http-request-ext'.'User-Agent' = 'Mozilla/5.0(Windows NT 6.1; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0']"
    ) == (
        "network-traffic:extensions.http-request-ext.User-Agent",
        "Mozilla/5.0(Windows NT 6.1; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0",
    )

    assert single_stix_equal_pattern(
        "[email:subject = 'Upcoming Defense events February 2018']"
    ) == (
        "email:subject",
        "Upcoming Defense events February 2018",
    )

    assert single_stix_equal_pattern(
        "[user-account:user_id = 'Asalah Al Sameeha']"
    ) == (
        "user-account:user_id",
        "Asalah Al Sameeha",
    )


def test_stix_pattern_not_ok() -> None:
    """test strix patterns that SHOULD fail"""
    with pytest.raises(ParseException):
        single_stix_equal_pattern("")

    with pytest.raises(MultipleComparisons):
        single_stix_equal_pattern(
            "[directory:path = '%APPDATA%' AND file:name = 'OneDrive.ps1']"
        )

    with pytest.raises(MultipleComparisons):
        single_stix_equal_pattern(
            "[network-traffic:protocols = 'https' AND network-traffic:dst_port = '443']"
        )

    with pytest.raises(MultipleComparisons):
        single_stix_equal_pattern(
            "[x509-certificate:issuer = 'CN=antivirus.comodo.com' AND x509-certificate:serial_number = '9c:28:e4:b3:cc:9b:47:b8:4b:29:23:af:e8:b0:d8:43' AND x509-certificate:validity_not_before = '2017-01-01T12:00:00Z' AND x509-certificate:validity_not_after = '2023-01-01T12:00:00Z']"
        )

    with pytest.raises(TypesNotString):
        assert single_stix_equal_pattern(
            "[domain-name:resolves_to_refs[*].value = '88.88.88.88']"
        )
