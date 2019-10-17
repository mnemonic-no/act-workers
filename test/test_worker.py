""" Tests for worker """
import sys

import _pytest
from act.workers.libs import worker


def test_args_origin_name(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    """ test argument origin-name """

    origin_name = "test-origin"

    monkeypatch.setattr(sys, "argv", ["./test-worker.py", "--origin-name", origin_name])

    args = worker.handle_args(worker.parseargs("Test worker"))
    actapi = worker.init_act(args)

    assert actapi.config.origin_name == origin_name

    fact = actapi.fact("mentions") \
        .source("report", "xyz")\
        .destination("fqdn", "test.com")

    assert fact.origin.name == origin_name


def test_args_origin_id(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    """ test argument origin-id """

    origin_id = "00000000-0000-0000-0000-000000000001"

    monkeypatch.setattr(sys, "argv", ["./test-worker.py", "--origin-id", origin_id])

    args = worker.handle_args(worker.parseargs("Test worker"))
    actapi = worker.init_act(args)

    assert actapi.config.origin_id == origin_id

    fact = actapi.fact("mentions") \
        .source("report", "xyz")\
        .destination("fqdn", "test.com")

    assert fact.origin.id == origin_id
