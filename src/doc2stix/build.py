"""Compact extraction -> STIX 2.1 bundle that OpenCTI imports as is.

- IDs are OpenCTI's deterministic IDs (pycti generate_id): the same malware
  extracted from two reports is one object in OpenCTI, and re-importing a
  bundle updates instead of duplicating.
- Each observable becomes an observable (SCO) plus an indicator with its STIX
  pattern, linked by based-on; "indicates" links the indicator to the actors or
  malware the document ties it to.
- A relationship is emitted only if OpenCTI allows its type between those two
  entity types (opencti_relationships.json); otherwise it is dropped and
  reported, never sent for OpenCTI to reject.
- Everything hangs off one Report (object_refs), with the source document as an
  external reference.
"""

import datetime as dt
import json
import uuid

import pycti
import stix2

from doc2stix import reference
from doc2stix.compact import REMAP, Extraction, Resolver

# STIX type and OpenCTI type of each compact entity type.
SDO = {
    "intrusion-set": ("intrusion-set", "Intrusion-Set"),
    "threat-actor": ("threat-actor", "Threat-Actor-Group"),
    "campaign": ("campaign", "Campaign"),
    "malware": ("malware", "Malware"),
    "tool": ("tool", "Tool"),
    "attack-pattern": ("attack-pattern", "Attack-Pattern"),
    "vulnerability": ("vulnerability", "Vulnerability"),
    "sector": ("identity", "Sector"),
    "organization": ("identity", "Organization"),
    "country": ("location", "Country"),
    "region": ("location", "Region"),
}
HASH_PATTERN = {"MD5": "MD5", "SHA-1": "'SHA-1'", "SHA-256": "'SHA-256'", "SHA-512": "'SHA-512'"}
SCO_CLASS = {
    "ipv4-addr": stix2.IPv4Address,
    "ipv6-addr": stix2.IPv6Address,
    "domain-name": stix2.DomainName,
    "url": stix2.URL,
    "email-addr": stix2.EmailAddress,
    "file": stix2.File,
}
NOW = "2026-01-01T00:00:00.000Z"  # fixed so builds are reproducible; OpenCTI sets its own dates


def stix_entity(e: dict, created_by: str) -> dict:
    stype, otype = SDO[e["type"]]
    name = e["name"]
    obj: dict = {
        "type": stype,
        "spec_version": "2.1",
        "name": name,
        "created": NOW,
        "modified": NOW,
        "created_by_ref": created_by,
    }
    if e.get("aliases"):
        key = "x_opencti_aliases" if stype in ("identity", "location") else "aliases"
        obj[key] = e["aliases"]
    match e["type"]:
        case "intrusion-set":
            obj["id"] = pycti.IntrusionSet.generate_id(name)
        case "threat-actor":
            obj["id"] = pycti.ThreatActorGroup.generate_id(name)
            obj["threat_actor_types"] = ["unknown"]
        case "campaign":
            obj["id"] = pycti.Campaign.generate_id(name)
        case "malware":
            obj["id"] = pycti.Malware.generate_id(name)
            obj["is_family"] = True
        case "tool":
            obj["id"] = pycti.Tool.generate_id(name)
        case "attack-pattern":
            tid = e.get("mitre_id")
            obj["id"] = pycti.AttackPattern.generate_id(name, tid)
            if tid:
                obj["x_mitre_id"] = tid
                obj["external_references"] = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                    }
                ]
        case "vulnerability":
            obj["id"] = pycti.Vulnerability.generate_id(name)
            obj["external_references"] = [
                {
                    "source_name": "cve",
                    "external_id": name,
                    "url": f"https://www.cve.org/CVERecord?id={name}",
                }
            ]
        case "sector":
            obj["id"] = pycti.Identity.generate_id(name, "class")
            obj["identity_class"] = "class"
            obj["x_opencti_type"] = "Sector"
        case "organization":
            obj["id"] = pycti.Identity.generate_id(name, "organization")
            obj["identity_class"] = "organization"
        case "country":
            obj["id"] = pycti.Location.generate_id(name, "Country")
            obj["country"] = name
            obj["x_opencti_location_type"] = "Country"
        case "region":
            obj["id"] = pycti.Location.generate_id(name, "Region")
            obj["region"] = name
            obj["x_opencti_location_type"] = "Region"
    return obj


def stix_observable(o: dict) -> tuple[dict, dict]:
    """The observable (SCO) and its indicator."""
    t, v = o["type"], o["value"]
    if t == "file":
        h = o["hash"]
        sco = {"type": "file", "spec_version": "2.1", "hashes": {h: v}}
        pattern = f"[file:hashes.{HASH_PATTERN[h]} = '{v}']"
        name = v
    else:
        sco = {"type": t, "spec_version": "2.1", "value": v}
        escaped = v.replace("\\", "\\\\").replace("'", "\\'")
        pattern = f"[{t}:value = '{escaped}']"
        name = v
    # STIX 2.1 deterministic SCO IDs (UUIDv5 of the ID-contributing properties),
    # the same standard_id OpenCTI computes.
    sco["id"] = SCO_CLASS[t](**{k: x for k, x in sco.items() if k in ("value", "hashes")}).id
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": pycti.Indicator.generate_id(pattern),
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": NOW,
        "created": NOW,
        "modified": NOW,
        "x_opencti_main_observable_type": {
            "ipv4-addr": "IPv4-Addr",
            "ipv6-addr": "IPv6-Addr",
            "domain-name": "Domain-Name",
            "url": "Url",
            "email-addr": "Email-Addr",
            "file": "StixFile",
        }[t],
    }
    return sco, indicator


def opencti_type(x: dict) -> str:
    if "value" in x:
        return "Observable"
    return SDO[x["type"]][1]


def relationship(rtype: str, src_id: str, tgt_id: str, created_by: str, description=None) -> dict:
    rel = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": pycti.StixCoreRelationship.generate_id(rtype, src_id, tgt_id),
        "relationship_type": rtype,
        "source_ref": src_id,
        "target_ref": tgt_id,
        "created": NOW,
        "modified": NOW,
        "created_by_ref": created_by,
    }
    if description:
        rel["description"] = description
    return rel


def author_identity(author: str) -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": pycti.Identity.generate_id(author, "organization"),
        "name": author,
        "identity_class": "organization",
        "created": NOW,
        "modified": NOW,
    }


def build_objects(ex: Extraction, created_by: str) -> tuple[list[dict], list[str]]:
    """The STIX objects of an extraction (entities, observables, indicators,
    relationships) and what was dropped (relationships OpenCTI would refuse).
    Used for a new report (build_bundle) and to enrich an existing entity."""
    dropped: list[str] = []
    objects: list[dict] = []
    ids: dict[int, str] = {}  # id(compact item) -> STIX id
    for e in ex.entities:
        obj = stix_entity(e, created_by)
        ids[id(e)] = obj["id"]
        objects.append(obj)
    indicator_of: dict[int, str] = {}
    for o in ex.observables:
        sco, ind = stix_observable(o)
        ind["created_by_ref"] = created_by
        ids[id(o)] = sco["id"]
        indicator_of[id(o)] = ind["id"]
        objects += [sco, ind, relationship("based-on", ind["id"], sco["id"], created_by)]
    allowed = reference.allowed_relationships()
    resolver = Resolver(ex)
    rels: dict[str, dict] = {}
    for r in ex.relationships:
        src, tgt = r["source"], r["target"]
        pair = f"{opencti_type(src)}|{opencti_type(tgt)}"
        rtype = REMAP.get((opencti_type(src), r["type"], opencti_type(tgt)), r["type"])
        if rtype not in allowed.get(pair, []) and rtype != "related-to":
            dropped.append(
                f"{opencti_type(src)} {rtype} {opencti_type(tgt)}: {_label(src)} -> {_label(tgt)}"
            )
            continue
        rel = relationship(rtype, ids[id(src)], ids[id(tgt)], created_by, r.get("evidence"))
        rels[rel["id"]] = rel
    for o in ex.observables:  # indicator --indicates--> actor / malware / campaign
        for name in o.get("indicates", []):
            tgt = resolver.find(name)
            if tgt is None or "value" in tgt:
                dropped.append(f"indicates: {o['value']} -> {name!r} (no such entity)")
                continue
            if "indicates" not in allowed.get(f"Indicator|{opencti_type(tgt)}", []):
                dropped.append(f"Indicator indicates {opencti_type(tgt)}: {o['value']}")
                continue
            rel = relationship("indicates", indicator_of[id(o)], ids[id(tgt)], created_by)
            rels[rel["id"]] = rel
    return objects + list(rels.values()), dropped


def build_bundle(
    ex: Extraction,
    *,
    title: str,
    published: str,
    source_url: str | None = None,
    author: str = "doc-to-stix",
    description: str | None = None,
) -> tuple[dict, list[str]]:
    """A new Report holding everything extracted, as a bundle, and what was dropped."""
    author_obj = author_identity(author)
    objects, dropped = build_objects(ex, author_obj["id"])
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": pycti.Report.generate_id(title, published),
        "name": title,
        "published": published,
        "report_types": ["threat-report"],
        "created": NOW,
        "modified": NOW,
        "created_by_ref": author_obj["id"],
        "object_refs": [o["id"] for o in objects] or [author_obj["id"]],
    }
    if description:
        report["description"] = description
    if source_url:
        report["external_references"] = [{"source_name": author, "url": source_url}]
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, report['id'])}",
        "objects": [author_obj, report, *objects],
    }
    return bundle, dropped


def _label(x: dict) -> str:
    return x.get("value") or x.get("mitre_id") or x["name"]


def dumps(bundle: dict) -> str:
    return json.dumps(bundle, ensure_ascii=False, indent=1)


def to_published(date: str) -> str:
    return dt.datetime.fromisoformat(date).strftime("%Y-%m-%dT00:00:00.000Z")
