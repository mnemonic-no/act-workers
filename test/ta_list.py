import pytest

#testing update_ta_aliases_list.py
def test_aliases_list():

    for sentence, [n, res] in tests:
        my_nlp = nlp.NLP(sentence)
        assert len(my_nlp.named_entities) == n
        for i, r in enumerate(my_nlp.named_entities):
            assert res[i] == r
            
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
