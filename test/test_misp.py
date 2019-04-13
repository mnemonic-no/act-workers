import pytest
from act.workers.libs import misp
import json
import uuid


def test_event():
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO

    a = misp.Event()
    output = StringIO()
    with pytest.raises(AttributeError):
        a.uuid = "GURBA"

    a.write_to(output)
    event = {"Event": json.loads(output.getvalue())}

    b = misp.Event(loads=json.dumps(event))

    assert a.uuid == b.uuid


def test_load_event():
    with open("test/misp_event.json") as event_f:
        a = misp.Event(loads=event_f.read())
    assert a.info == 'M2M -  Dridex 2017-11-14 : botnet 7200 : "Invoice No.\n 123456" - "Invoice-123456-06.doc"'
    assert a.uuid == uuid.UUID("5a0f0fb1-0b54-4ace-bb7b-429f950d210f")
    assert a.date == "2017-11-17"
    assert a.published is False
    assert a.threat_level_id == misp.ThreatLevelID.LOW
    assert a.analysis == misp.Analysis.ONGOING
    assert "tool" in a.misp_galaxy
    assert a.misp_galaxy.get("tool", "") == "Dridex"
