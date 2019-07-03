""" Test for scio worker """
import json

import act.api
from act.workers import scio


def test_scio_facts(capsys) -> None:  # type: ignore
    """ Test for scio facts, by comparing to captue of stdout """
    with open("test/scio-doc.json") as scio_doc:
        doc = json.loads(scio_doc.read())

    api = act.api.Act("", None, "error")

    scio.add_to_act(api, doc, output_format="str")

    captured = capsys.readouterr()
    facts = set(captured.out.split("\n"))

    report_id = doc["hexdigest"]

    sha256 = doc["indicators"]["sha256"][0]
    uri = doc["indicators"]["uri"][0] # "http://www.us-cert.gov/tlp."

    fact_assertions = [
        api.fact("name", "TA18-149A.stix.xml").source("report", report_id),
        api.fact("mentions", "ipv4").source("report", report_id).destination("ipv4", "187.127.112.60"),
        api.fact("mentions", "hash").source("report", report_id).destination("hash", "4613f51087f01715bf9132c704aea2c2"),
        api.fact("mentions", "hash").source("report", report_id).destination("hash", sha256),
        api.fact("mentions", "country").source("report", report_id).destination("country", "Colombia"),
        api.fact("mentions", "uri").source("report", report_id).destination("uri", uri),
        api.fact("componentOf").source("fqdn", "www.us-cert.gov").destination("uri", uri),
        api.fact("componentOf").source("path", "/tlp.").destination("uri", uri),
        api.fact("scheme", "http").source("uri", uri),
        api.fact("mentions", "tool").source("report", report_id).destination("tool", "kore"),
        api.fact("mentions", "uri").source("report", report_id).destination("uri", "email://redhat@gmail.com"),
        api.fact("mentions", "ipv4Network").source("report", report_id).destination("ipv4Network", "192.168.0.0/16"),
        api.fact("represents").source("hash", sha256).destination("content", sha256)
    ]

    for fact_assertion in fact_assertions:
        assert str(fact_assertion) in facts
