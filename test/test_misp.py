import json
import uuid

import pytest

from act.workers import misp_feeds
from act.workers.libs import misp


@pytest.mark.server(
    url="/manifest.json",
    response=json.load(open("test/data/misp_dir/manifest.json")),
    method="GET",
)
@pytest.mark.server(
    url="/57e27c3d-17a8-4c3b-8195-493e950d210f.json",
    response=json.load(
        open("test/data/misp_dir/57e27c3d-17a8-4c3b-8195-493e950d210f.json")
    ),
    method="GET",
)
@pytest.mark.server(
    url="/5721c2e4-05ec-4af3-9264-411b950d210f.json",
    response=json.load(
        open("test/data/misp_dir/5721c2e4-05ec-4af3-9264-411b950d210f.json")
    ),
    method="GET",
)
def test_event() -> None:
    info = [
        "Malspam (2016-04-28) - Locky (#2)",
        'Malspam 2016-09-21 (.wsf in .zip) - campaign: "E-TICKET {integer}"',
    ]
    uuids = [
        "5721c2e4-05ec-4af3-9264-411b950d210f",
        "57e27c3d-17a8-4c3b-8195-493e950d210f",
    ]
    dates = ["2016-04-28", "2016-09-21"]

    for event in misp_feeds.handle_feed("NODIR", "http://localhost:5000"):
        assert event.published
        assert str(event.uuid) in uuids
        assert event.date in dates
        assert event.threat_level_id == misp.ThreatLevelID.LOW
        assert not event.extends_uuid
        assert event.analysis in [misp.Analysis.INITIAL, misp.Analysis.COMPLETE]
        assert event.info in info


def test_load_event() -> None:
    with open("test/misp_event.json") as event_f:
        a = misp.Event(loads=event_f.read())
    assert (
        a.info
        == 'M2M -  Dridex 2017-11-14 : botnet 7200 : "Invoice No.\n 123456" - "Invoice-123456-06.doc"'
    )
    assert (
        a.sha256 == "c06ffa7a7a0da5c61a38916c11a2f4bb3e74ac18d3e24e727cef78e2d2b2e781"
    )
    assert a.uuid == uuid.UUID("5a0f0fb1-0b54-4ace-bb7b-429f950d210f")
    assert a.date == "2017-11-17"
    assert a.published is False
    assert a.threat_level_id == misp.ThreatLevelID.LOW
    assert a.analysis == misp.Analysis.ONGOING
    assert "tool" in a.misp_galaxy
    assert a.misp_galaxy.get("tool", "") == "Dridex"
