"""Import a bundle into OpenCTI and check what OpenCTI actually created.

"Usable by OpenCTI" is measured, not assumed: every object of the bundle is sent
through the API (pycti, the library connectors use), then the report is read back
and its contents compared with the bundle.

Settings: OPENCTI_URL (default http://localhost:8088) and OPENCTI_TOKEN, or the
admin token in infra/opencti/.env.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[2] / "infra" / "opencti" / ".env"


def settings() -> tuple[str, str]:
    url = os.environ.get("OPENCTI_URL", "http://localhost:8088")
    token = os.environ.get("OPENCTI_TOKEN")
    if not token and ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("OPENCTI_ADMIN_TOKEN="):
                token = line.split("=", 1)[1].strip()
    if not token:
        raise SystemExit("set OPENCTI_TOKEN (or create infra/opencti/.env)")
    return url, token


def client():
    from pycti import OpenCTIApiClient

    logging.getLogger("pycti").setLevel(logging.ERROR)
    url, token = settings()
    return OpenCTIApiClient(url, token, log_level="error", ssl_verify=False)


@dataclass
class ImportCheck:
    """What OpenCTI holds after the import.

    OpenCTI merges a relationship into an existing one with the same type and
    ends (one the MITRE connector loaded, say) without recording the bundle's ID
    for it; the report's reference to that ID is then dropped. So relationships
    are checked twice: do they exist in OpenCTI, and are they in the report."""

    entities_sent: int = 0
    entities_in_report: int = 0
    relationships_sent: int = 0
    relationships_exist: int = 0
    relationships_in_report: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            not self.errors
            and self.entities_in_report == self.entities_sent
            and self.relationships_exist == self.relationships_sent
        )

    def summary(self) -> str:
        return (
            f"entities {self.entities_in_report}/{self.entities_sent} in report, "
            f"relationships {self.relationships_exist}/{self.relationships_sent} exist "
            f"({self.relationships_in_report} in report)"
        )


REPORT_OBJECTS = """query R($id: String!) { report(id: $id) { objects(first: 5000) { edges { node {
  ... on StixObject { standard_id x_opencti_stix_ids }
  ... on StixCoreRelationship { relationship_type
     from { ... on StixObject { standard_id } }
     to { ... on StixObject { standard_id } } } } } } } }"""


def import_and_check(bundle: dict, api=None) -> ImportCheck:
    api = api or client()
    check = ImportCheck()
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    byid = {o["id"]: o for o in bundle["objects"]}
    sent = [byid[i] for i in report["object_refs"] if i in byid]
    rels = [o for o in sent if o["type"] == "relationship"]
    check.entities_sent = len(sent) - len(rels)
    check.relationships_sent = len(rels)
    try:
        # The way OpenCTI's workers import a connector's bundle: split in dependency order.
        from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

        _, _, parts = OpenCTIStix2Splitter().split_bundle_with_expectations(
            bundle=json.dumps(bundle), use_json=True, event_version=None
        )
        for part in parts:
            api.stix2.import_bundle_from_json(part, update=True)
    except Exception as exc:  # noqa: BLE001 - every failure is a finding
        check.errors.append(f"import failed: {exc}")
        return check
    data = api.query(REPORT_OBJECTS, {"id": report["id"]})["data"]["report"]
    if not data:
        check.errors.append(f"report {report['id']} not found after import")
        return check
    nodes = [e["node"] for e in data["objects"]["edges"]]
    ids = set()
    triples = set()
    for n in nodes:
        ids.add(n.get("standard_id"))
        ids.update(n.get("x_opencti_stix_ids") or [])
        if n.get("relationship_type"):
            triples.add(
                (
                    n["relationship_type"],
                    (n.get("from") or {}).get("standard_id"),
                    (n.get("to") or {}).get("standard_id"),
                )
            )
    check.entities_in_report = sum(
        1 for o in sent if o["type"] != "relationship" and o["id"] in ids
    )
    for r in rels:
        t = (r["relationship_type"], r["source_ref"], r["target_ref"])
        if t in triples:
            check.relationships_in_report += 1
            check.relationships_exist += 1
            continue
        src, tgt = internal_id(api, r["source_ref"]), internal_id(api, r["target_ref"])
        if (
            src
            and tgt
            and api.stix_core_relationship.list(
                fromId=src, toId=tgt, relationship_type=[r["relationship_type"]], first=1
            )
        ):
            check.relationships_exist += 1
    return check


_internal: dict[str, str | None] = {}
SCO_TYPES = ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file")


def internal_id(api, stix_id: str) -> str | None:
    """OpenCTI's internal ID of an object known by its STIX ID (relationship
    filters take internal IDs)."""
    if stix_id not in _internal:
        sco = stix_id.split("--")[0] in SCO_TYPES
        obj = (api.stix_cyber_observable if sco else api.stix_core_object).read(id=stix_id)
        _internal[stix_id] = obj["id"] if obj else None
    return _internal[stix_id]
