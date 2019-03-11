""" Test for scio worker """
import json

import pytest

import act
import scio_worker


def test_scio_facts(capsys) -> None:  # type: ignore
    """ Test for scio facts, by comparing to captue of stdout """
    with open("test/scio-doc.json") as scio_doc:
        doc = json.loads(scio_doc.read())

    api = act.Act("", None, "error")

    scio_worker.add_to_act(api, doc)

    captured = capsys.readouterr()
    facts = set(captured.out.split("\n"))

    report_id = doc["hexdigest"]

    fact_assertions = [
        api.fact("name", "TA18-149A.stix.xml").source("report", report_id),
        api.fact("mentions", "ipv4").source("report", report_id).destination("ipv4", "187.127.112.60"),
        api.fact("mentions", "hash").source("report", report_id).destination("hash", "4613f51087f01715bf9132c704aea2c2"),
        api.fact("mentions", "hash").source("report", report_id).destination("hash", "077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885"),
        api.fact("mentions", "country").source("report", report_id).destination("country", "Colombia"),
        api.fact("mentions", "tool").source("report", report_id).destination("tool", "kore"),
        api.fact("mentions", "email").source("report", report_id).destination("email", "redhat@gmail.com")
    ]

    for fact_assertion in fact_assertions:
        assert str(fact_assertion) in facts
