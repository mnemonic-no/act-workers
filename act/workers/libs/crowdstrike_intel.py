#!/usr/bin/env python
from datetime import datetime
from logging import debug, warning
from typing import Any, Dict, Iterator, List, Set

from falconpy import Intel
from pydantic import BaseModel, Field, validator
from pydantic.typing import Literal  # type: ignore

KILL_CHAIN_TYPE = Literal[
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "c2",
    "actiononobjectives",
]


class APIError(BaseModel):
    code: str
    message: str


class CrowdStrikeAPIError(Exception):
    """Exception class used to report errors from the API"""

    def __init__(self, response: Dict[str, Any]):
        self.errors = [APIError(**error) for error in response["body"]["errors"]]

    def __str__(self) -> str:
        return ", ".join(f"{error.code}: {error.message}" for error in self.errors)


class Label(BaseModel):
    created_on: datetime
    last_valid_on: datetime
    name: str


class Relation(BaseModel):
    created_date: datetime
    id: str
    indicator: str
    last_valid_date: datetime
    type: str


class Indicator(BaseModel):
    marker: str = Field(alias="_marker")
    actors: Set[str]
    deleted: bool
    domain_types: Set[str]
    id: str
    indicator: str
    ip_address_types: Set[str]
    kill_chains: Set[KILL_CHAIN_TYPE]
    labels: List[Label]
    last_updated: datetime
    malicious_confidence: str
    published_date: datetime
    relations: List[Relation]
    reports: Set[str]
    targets: Set[str]
    threat_types: Set[str]
    type: str
    vulnerabilities: Set[str]
    malware_families: Set[str]

    @validator("kill_chains", each_item=True, pre=True)
    def to_lower(cls, v: str) -> str:
        return v.lower()


class Slug(BaseModel):
    """
    Slug is a generic type that is returned by som objecsts where we have
    id: numeric value
    slug: identifier (string)
    value: name

    Example:

        Slug(id=344, slug='government', value='Government')
    """

    id: int
    slug: str
    value: str


class Actor(BaseModel):
    active: bool
    capabilities: List[Slug]
    created_date: datetime
    first_activity_date: datetime
    id: int
    known_as: List[str]
    last_activity_date: datetime
    last_modified_date: datetime
    motivations: List[Slug]
    name: str
    notify_users: bool
    objectives: List[Slug]
    origins: List[Slug]
    short_description: str
    slug: str
    status: str
    target_countries: List[Slug]
    target_industries: List[Slug]
    target_regions: List[Slug]
    url: str

    @validator("known_as", pre=True)
    def to_list(cls, value: str) -> List[str]:
        """known_as is a comma separated list, convert to list of strings"""
        return [v.strip() for v in value.split(",") if v.strip()]

    # Replace None values with empty list
    @validator("capabilities", pre=True)
    def empty_capabilities(cls, v: Any) -> Any:
        if not v:
            return []
        return v

    @validator("motivations", pre=True)
    def empty_motivations(cls, v: Any) -> Any:
        if not v:
            return []
        return v

    @validator("objectives", pre=True)
    def empty_objectives(cls, v: Any) -> Any:
        if not v:
            return []
        return v

    @validator("origins", pre=True)
    def empty_origins(cls, v: Any) -> Any:
        if not v:
            return []
        return v

    @validator("target_countries", pre=True)
    def empty_target_countries(cls, v: Any) -> Any:
        if not v:
            return []
        return v

    @validator("target_industries", pre=True)
    def empty_target_industries(cls, v: Any) -> Any:
        if not v:
            return []
        return v

    @validator("target_regions", pre=True)
    def empty_target_regions(cls, v: Any) -> Any:
        if not v:
            return []
        return v


def get_actors(falcon: Intel) -> Iterator[Actor]:
    """Get actors"""

    # No need to process in batches, there are currently only ~200 entries
    response = falcon.query_actor_entities(limit=5000, filter=None)

    if response["status_code"] == 200:
        for resource in response["body"]["resources"]:
            yield Actor(**resource)
    else:
        raise CrowdStrikeAPIError(response)


def get_latest_indicators(
    falcon: Intel,
    last_indicator: str,
    batch_size: int = 5000,
    limit: int = 0,
) -> Iterator[Indicator]:
    """
    Pagination logic from
    https://www.falconpy.io/Usage/Response-Handling.html#paginating-json-responses
    """

    # Calculate our current timestamp in seconds (%s),
    # we will use this value for our _marker timestamp.
    current_page = last_indicator

    sort = "_marker.asc"
    total = 1
    count = 0

    while total > 0:
        # _marker has timestamp as a prefix: e.g. 1679900908ecdc33f45ad3a9c3a6a60946fa5b99a4
        response = falcon.query_indicator_entities(
            limit=batch_size, sort=sort, filter=f"_marker:>'{current_page}'"
        )

        if response["status_code"] == 200:
            page = response["body"]["meta"]["pagination"]
            total = page["total"]

            resources = response["body"]["resources"]

            debug(
                f"Retrieved: {len(resources)}, Remaining: {total}, Marker: {current_page}"
            )

            if resources:
                current_page = resources[-1].get("_marker", "")

            for indicator in resources:
                yield Indicator(**indicator)
                count = +1

                if limit and limit > count:
                    warning(f"Reached: {limit} indicators and will exit")
                    return

        else:
            raise CrowdStrikeAPIError(response)
