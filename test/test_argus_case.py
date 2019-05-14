""" Test for argus case worker """
import json

import act.api
from act.workers.libs import argus


# pylint: disable=too-many-locals
def test_argus_case_facts(capsys, caplog) -> None:  # type: ignore
    """ Test for argus case facts, by comparing to captue of stdout """
    with open("test/data/argus-event.json") as argus_event:
        event = json.loads(argus_event.read())

    api = act.api.Act("", None, "error")

    argus.handle_argus_event(api, event, output_format="str")

    captured = capsys.readouterr()
    facts = set(captured.out.split("\n"))
    logs = [rec.message for rec in caplog.records]

    # print(captured.out)

    prop = event["properties"]
    uri = event["uri"]
    incident_id = "ARGUS-{}".format(event["associatedCase"]["id"])
    alert_id = event["id"]

    # Fact chain from md5 hash through content to alert
    md5_chain = act.api.fact.fact_chain(
        api.fact("represents")
        .source("hash", prop["file.md5"])
        .destination("content", "*"),
        api.fact("observedIn", "alert")
        .source("content", "*")
        .destination("alert", alert_id)
    )

    sha256 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

    fact_assertions = [
        api.fact("observedIn", "incident").source("alert", alert_id).destination("incident", incident_id),

        api.fact("observedIn", "alert").source("content", sha256).destination("alert", alert_id),
        api.fact("observedIn", "alert").source("uri", uri).destination("alert", alert_id),
        api.fact("observedIn", "alert").source("fqdn", event["domain"]["fqdn"]).destination("alert", alert_id),
        api.fact("componentOf").source("fqdn", "test-domain.com").destination("uri", uri),
        api.fact("componentOf").source("path", "/path.cgi").destination("uri", uri),
        api.fact("scheme", "http").source("uri", uri),
        api.fact("observedIn", "alert").source("uri", "tcp://1.2.3.4").destination("alert", alert_id),
    ]

    fact_negative_assertions = [

        # This fact should not exist, since we only add IPs with public addresses
        api.fact("observedIn", "alert").source("uri", "tcp://192.168.1.1").destination("alert", alert_id),

        # Not valid content hash (sha256)
        api.fact("observedIn", "alert").source("content", "bogus").destination("alert", alert_id),
    ]

    assert 'Illegal sha256: "bogus" in property "file.sha256"' in logs

    for fact_assertion in fact_assertions:
        assert str(fact_assertion) in facts

    for fact_assertion in fact_negative_assertions:
        assert str(fact_assertion) not in facts

    for fact_assertion in md5_chain:
        assert str(fact_assertion) in facts
