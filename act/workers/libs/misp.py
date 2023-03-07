"""Library for working with MISP export files"""

import enum
import hashlib
import ipaddress
import json
import re
import time
import uuid
from logging import debug, warning
from typing import Callable, Dict, Optional, Text, Tuple


class ThreatLevelID(enum.Enum):
    """2.2.1.5.  threat_level_id

    threat_level_id represents the threat level.

    4:   Undefined
    3:   Low
    2:   Medium
    1:   High

    If a higher granularity is required, a MISP taxonomy applied as a Tag
    SHOULD be preferred.

    threat_level_id SHALL be present."""

    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNDEFINED = 4


class Analysis(enum.Enum):
    """2.2.1.6.  analysis

    analysis represents the analysis level.

    0:   Initial
    1:   Ongoing
    2:   Complete

    If a higher granularity is required, a MISP taxonomy applied as a Tag
    SHOULD be preferred.

    analysis SHALL be present."""

    INITIAL = 0
    ONGOING = 1
    COMPLETE = 2


class Distribution(enum.Enum):
    """2.2.1.13.  distribution

    distribution represents the basic distribution rules of the event.  The
    system must adhere to the distribution setting for access control and for
    dissemination of the event.

    distribution MUST be present and be one of the following options:

    0 Your Organisation Only
    1 This Community Only
    2 Connected Communities
    3 All Communities
    4 Sharing Group"""

    ORGANIZATION_ONLY = 0
    COMMUNITY_ONLY = 1
    CONNECTED_COMMUNITIES = 2
    ALL_COMMUNITIES = 3
    SHARING_GROUP = 4
    INHERIT_EVENT = 5


class Event:  # pylint: disable=R0902
    """Event represents a MISP event"""

    # --- MUST ----
    published = None
    info = None
    threat_level_id = ThreatLevelID.UNDEFINED
    analysis = Analysis.INITIAL
    date = None  # ISO-8601 (date only: YYYY-MM-DD) reference date of the event
    org_id = None  # Human readable org. generating the Event
    orgc_id = None  # Human readble org. *creating* the Event
    attribute_count = 0
    distribution = Distribution.ORGANIZATION_ONLY
    sharing_group_id = None
    # --- END_MUST ----

    # --- SHOULD ---
    extends_uuid = None
    # --- END_SHOULD ---

    tlp = None
    misp_galaxy: Dict[Text, Text] = {}

    def __init__(self, loads: Optional[Text] = None) -> None:
        self._uuid: uuid.UUID = uuid.uuid4()
        self.timestamp: int = int(
            time.time()
        )  # Timestamp of event creation or event/attribute last update
        self.publish_timestamp: int = int(
            time.time()
        )  # reference time when the event was published on the instance.

        self.sha256 = None

        if loads:
            data = json.loads(loads)
            event = data["Event"]

            self.sha256 = hashlib.sha256(loads.encode("utf-8")).hexdigest()
            self._uuid = uuid.UUID(event["uuid"])
            self.published = event["published"]
            self.info = event["info"]
            self.threat_level_id = ThreatLevelID(int(event["threat_level_id"]))
            self.analysis = Analysis(int(event["analysis"]))
            self.date = event["date"]
            self.timestamp = event["timestamp"]

            if "publish_timestamp" in event:
                self.publish_timestamp = event["publish_timestamp"]
            else:
                warning("publish_timestamp missing in event %s", event)
            self.org_id = event.get("org_id", "N/A")
            self.orgc_id = event.get("orgc_id", "N/A")
            self.attribute_count = event.get("attribute_count", 0)
            self.distribution = Distribution(int(event.get("distribution", 0)))
            self.sharing_group_id = event.get("sharing_group_id", None)
            self.extends_uuid = event.get("extends_uuid", None)

            misp_re = re.compile(r'misp-galaxy:(.*?)="(.*?)"')
            for tag in event.get("Tag", []):
                name = tag["name"]
                if name.startswith("tlp"):
                    self.tlp = name.split(":")[1]
                if name.startswith("misp-galaxy"):
                    for match in misp_re.findall(name):
                        self.misp_galaxy[match[0]] = match[1]

            self.attributes = [Attribute(e) for e in event.get("Attribute", [])]
            objects = event.get("Object", [])
            for obj in objects:
                obj_attributes = obj.get("Attribute", [])
                self.attributes += [Attribute(e) for e in obj_attributes]

    def __str__(self) -> Text:
        return "({0}) {1} - {2} ".format(self.timestamp, self._uuid, self.info)

    @property
    def uuid(self):  # type: ignore
        """The Event UUID property"""
        return self._uuid


class Attribute:  # attributeattributes in misp babel pylint: disable=R0903
    """Represents a MISP attribute, performing the neccessary translations between
    misp and act namespaces"""

    def __init__(self, attributedict: Dict[Text, Text]):

        self._uuid = attributedict["uuid"]
        self.id: Text = attributedict["uuid"]
        mapper_fn = map_misp_to_act.get(attributedict["type"], lambda x: (None, None))
        self.act_type: Optional[Text] = None
        self.value: Optional[Text] = None

        self.act_type, self.value = mapper_fn(attributedict["value"])

        if "RelatedAttribute" in attributedict and attributedict["RelatedAttribute"]:
            debug("Related atribute: %s", attributedict["RelatedAttribute"])

    def __str__(self) -> Text:
        return "{0} {1}:{2}".format(self.id, self.act_type, self.value)


def hash_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "hash", x.lower()


def certificate_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "certificate", x.lower()


def threat_actor_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "threatActor", x


def campaign_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "campaign", x.lower()


def email_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "uri", "email://{}".format(x.lower())


def person_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "person", x.lower()


def organization_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "organization", x.lower()


def fqdn_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "fqdn", x.lower()


def ip_f(x: Text) -> Tuple[Optional[Text], Optional[Text]]:
    """Translation function misp -> act"""
    try:
        addrv6 = ipaddress.IPv6Address(x)
        return "ipv6", str(addrv6.exploded)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Address(x)
            return "ipv4", x
        except ipaddress.AddressValueError:
            pass

    return None, None


def uri_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    if not x.startswith("http"):
        x = "http://{0}".format(x)
    return "uri", x


def user_agent_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "userAgent", x


def vulnerability_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "vulnerability", x.lower()


def mutex_f(x: Text) -> Tuple[Text, Text]:
    """Translation function misp -> act"""
    return "mutex", x


map_misp_to_act: Dict[Text, Callable[[Text], Tuple[Optional[Text], Optional[Text]]]] = {
    "authentihash": hash_f,
    "campaign-name": campaign_f,
    "hostname": fqdn_f,
    "domain": fqdn_f,
    "impfuzzy": hash_f,
    "imphash": hash_f,
    "ip-dst": ip_f,
    "ip-src": ip_f,
    "link": uri_f,
    "md5": hash_f,
    "mutex": mutex_f,
    "sha1": hash_f,
    "sha224": hash_f,
    "sha256": hash_f,
    "sha384": hash_f,
    "sha512/224": hash_f,
    "sha512/256": hash_f,
    "sha512": hash_f,
    "ssdeep": hash_f,
    "threat-actor": threat_actor_f,
    "url": uri_f,
    "user-agent": user_agent_f,
    "vulnerability": vulnerability_f,
    "whois-registrant-email": email_f,
    "whois-registrant-name": person_f,
    "whois-registrar": organization_f,
    "x509-fingerprint-sha1": certificate_f,
}
