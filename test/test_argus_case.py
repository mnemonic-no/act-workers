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

    argus.handle_argus_event(
        api,
        event,
        content_props=["file.sha256", "process.sha256"],
        hash_props=["file.md5", "process.md5", "file.sha1", "process.sha1", "file.sha512", "process.sha512"],
        output_format="str")

    captured = capsys.readouterr()
    facts = set(captured.out.split("\n"))
    logs = [rec.message for rec in caplog.records]

    print(captured.out)

    prop = event["properties"]
    uri = event["uri"]
    incident_id = "ARGUS-{}".format(event["associatedCase"]["id"])
    event_id = "ARGUS-{}".format(event["id"])

    signature = event["attackInfo"]["signature"]

    # Fact chain from md5 hash through content to alert
    md5_chain = act.api.fact.fact_chain(
        api.fact("represents")
        .source("hash", prop["file.md5"])
        .destination("content", "*"),
        api.fact("observedIn", "event")
        .source("content", "*")
        .destination("event", event_id)
    )

    sha256 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

    fact_assertions = [
        api.fact("attributedTo", "incident").source("event", event_id).destination("incident", incident_id),
        api.fact("observedIn", "event").source("content", sha256).destination("event", event_id),
        api.fact("detects", "event").source("signature", signature).destination("event", event_id),
        api.fact("name", "Infected host").source("incident", incident_id),
        api.fact("observedIn", "event").source("uri", uri).destination("event", event_id),
        api.fact("componentOf").source("fqdn", "test-domain.com").destination("uri", uri),
        api.fact("componentOf").source("path", "/path.cgi").destination("uri", uri),
        api.fact("scheme", "http").source("uri", uri),
        api.fact("observedIn", "event").source("uri", "tcp://1.2.3.4").destination("event", event_id),
    ]

    fact_negative_assertions = [
        # This fact should not exist, since we only add IPs with public addresses
        api.fact("observedIn", "event").source("uri", "tcp://192.168.1.1").destination("event", event_id),

        # We have URI, so this should not be constructed from the fqdn
        api.fact("observedIn", "event").source("uri", "tcp://test-domain.com").destination("event", event_id),

        # Not valid content hash (sha256)
        api.fact("observedIn", "event").source("content", "bogus").destination("event", event_id),
    ]

    assert 'Illegal sha256: "bogus" in property "file.sha256"' in logs

    for fact_assertion in fact_assertions:
        assert str(fact_assertion) in facts

    for fact_assertion in fact_negative_assertions:
        assert str(fact_assertion) not in facts

    for fact_assertion in md5_chain:
        assert str(fact_assertion) in facts
