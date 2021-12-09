""" Tests for worker """
import sys

import _pytest
import act.api
import pytest
from act.api.base import ValidationError
from act.api.helpers import handle_fact
from act.api.libs import cli
from act.types.format import object_format
from act.types.types import object_validates

from act.workers.libs import worker


def test_args_origin_name(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    """test argument origin-name"""

    origin_name = "test-origin"

    monkeypatch.setattr(sys, "argv", ["./test-worker.py", "--origin-name", origin_name])

    args = cli.handle_args(worker.parseargs("Test worker"))
    actapi = worker.init_act(args)

    assert actapi.config.origin_name == origin_name

    fact = (
        actapi.fact("mentions").source("report", "xyz").destination("fqdn", "test.com")
    )

    assert fact.origin.name == origin_name


def test_args_origin_id(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    """test argument origin-id"""

    origin_id = "00000000-0000-0000-0000-000000000001"

    monkeypatch.setattr(sys, "argv", ["./test-worker.py", "--origin-id", origin_id])

    args = cli.handle_args(worker.parseargs("Test worker"))
    actapi = worker.init_act(args)

    assert actapi.config.origin_id == origin_id

    fact = (
        actapi.fact("mentions").source("report", "xyz").destination("fqdn", "test.com")
    )

    assert fact.origin.id == origin_id


def test_validator_no_strict(caplog) -> None:
    api = act.api.Act(
        "",
        None,
        object_formatter=object_format,
        object_validator=object_validates,
    )

    # Should return None if fact does not validate
    fact = handle_fact(
        api.fact("mentions")
        .source("report", "xyz")
        .destination("uri", "X7f://cve-2014-0224")
    )

    assert fact is None

    assert "Destination object does not validate:" in caplog.text


def test_validate_same_object() -> None:
    api = act.api.Act(
        "",
        None,
        strict_validator=True,
        object_formatter=object_format,
        object_validator=object_validates,
    )

    act.api.helpers.handle_fact.cache_clear()

    with pytest.raises(ValidationError, match=r"Source object can not be equal to.*"):
        handle_fact(
            api.fact("mentions").source("report", "xyz").destination("report", "xyz")
        )


def test_validator_no_validator(caplog) -> None:
    api = act.api.Act("", None)
    act.api.helpers.handle_fact.cache_clear()

    # Should return None if fact does not validate
    fact = handle_fact(
        api.fact("mentions")
        .source("report", "xyz")
        .destination("uri", "X7f://cve-2014-0224")
    )

    # No validator is specified so the above should return a fact
    assert fact is not None

    # Should not log errors
    assert caplog.text == ""


def test_validator_strict() -> None:
    api = act.api.Act(
        "",
        None,
        strict_validator=True,
        object_formatter=object_format,
        object_validator=object_validates,
    )
    act.api.helpers.handle_fact.cache_clear()

    with pytest.raises(
        ValidationError, match=r"Destination object does not validate.*"
    ):

        handle_fact(
            api.fact("mentions")
            .source("report", "xyz")
            .destination("uri", ".X7f://cve-2014-0224")
        )


def test_format() -> None:
    api = act.api.Act(
        "",
        None,
        object_formatter=object_format,
        object_validator=object_validates,
    )
    act.api.helpers.handle_fact.cache_clear()

    ta_alias = handle_fact(
        api.fact("alias")
        .source("threatActor", "APT29")
        .destination("threatActor", "Cozy Bear")
    )

    assert ta_alias.source_object.value == "apt29"
    assert ta_alias.destination_object.value == "cozy bear"
