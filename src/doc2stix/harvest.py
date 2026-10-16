"""What a document writes literally: ATT&CK IDs, CVE IDs, hashes, defanged IOCs.

Advisories list techniques by ID in long tables and IOCs by the hundred; a model
reading chunk by chunk misses many of them (engine 0.1: 14% of the 165
techniques of the APT40 advisory). A pattern finds them all. The model keeps
the part that needs reading: names, relationships, techniques described in
prose. Each harvested item carries the line it was found on as evidence.

Harvested techniques that the model linked to nobody are given to the main
subject of the document (guidelines: "when the document does not say, to the
main subject of the advisory").
"""

import ipaddress
import re
from collections import Counter

from doc2stix import compact, reference

TECHNIQUE = re.compile(r"(?<![\w.])(T[01]\d{3}(?:\.\d{3})?)(?![\w.]\d)")
CVE = re.compile(r"\bCVE[-‐–]\d{4}[-‐–]\d{4,7}\b", re.I)
HASH = re.compile(
    r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
DEFANGED = re.compile(r"\S*(?:\[\.\]|\(\.\)|\[dot\]|hxxps?|\[:\]|\[@\])\S*", re.I)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SUBJECT_TYPES = ("intrusion-set", "threat-actor", "campaign", "malware")


def line_of(text: str, start: int) -> str:
    a = text.rfind("\n", 0, start) + 1
    b = text.find("\n", start)
    return text[a : b if b != -1 else len(text)].strip()[:200]


def harvest(text: str) -> dict:
    """Entities and observables written literally in the text (compact format)."""
    entities, observables = [], []
    seen = set()
    for m in TECHNIQUE.finditer(text):
        tid = reference.current_technique(m.group(1))
        if tid and ("ap", tid) not in seen:
            seen.add(("ap", tid))
            entities.append(
                {
                    "type": "attack-pattern",
                    "name": reference.techniques()[tid],
                    "mitre_id": m.group(1),
                    "evidence": line_of(text, m.start()),
                }
            )
    for m in CVE.finditer(text):
        cve = re.sub(r"[‐–]", "-", m.group(0)).upper()
        if ("cve", cve) not in seen:
            seen.add(("cve", cve))
            entities.append(
                {"type": "vulnerability", "name": cve, "evidence": line_of(text, m.start())}
            )
    for m in HASH.finditer(text):
        h = m.group(1).lower()
        if ("h", h) not in seen:
            seen.add(("h", h))
            observables.append({"type": "file", "value": h})
    for m in DEFANGED.finditer(text):
        v = compact.refang(m.group(0)).strip(".,;:()[]")
        otype = guess_type(v)
        if otype and (otype, v.lower()) not in seen:
            seen.add((otype, v.lower()))
            observables.append({"type": otype, "value": v})
    for m in IPV4.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        if ip.is_global and ("ipv4-addr", str(ip)) not in seen:
            seen.add(("ipv4-addr", str(ip)))
            observables.append({"type": "ipv4-addr", "value": str(ip)})
    return {"entities": entities, "observables": observables, "relationships": []}


def guess_type(v: str) -> str | None:
    if re.match(r"^(https?|ftp)://", v, re.I):
        return "url"
    if "@" in v and re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", v, re.I):
        return "email-addr"
    try:
        ipaddress.IPv4Address(v)
        return "ipv4-addr"
    except ValueError:
        pass
    if re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", v, re.I):
        return "domain-name"
    return None


def main_subject(text: str, entities: list[dict]) -> str | None:
    """The actor or malware the document is about: the most mentioned one."""
    counts = Counter()
    for e in entities:
        if e["type"] in SUBJECT_TYPES:
            names = [e["name"], *e.get("aliases", [])]
            counts[e["name"]] = sum(len(re.findall(re.escape(n), text, re.I)) for n in names)
    if not counts:
        return None
    name, n = counts.most_common(1)[0]
    return name if n > 0 else None


def merge(model: dict, text: str) -> dict:
    """The model's extraction plus what the text writes literally; harvested
    techniques nobody uses go to the main subject."""
    found = harvest(text)
    out = {
        k: list(model.get(k) or []) + found[k] for k in ("entities", "observables", "relationships")
    }
    parsed = compact.parse(out)
    used = {
        r["target"].get("mitre_id")
        for r in parsed.relationships
        if r["type"] == "uses" and r["target"].get("type") == "attack-pattern"
    }
    subject = main_subject(text, parsed.entities)
    if subject:
        for e in found["entities"]:
            tid = (
                reference.current_technique(e["mitre_id"])
                if e["type"] == "attack-pattern"
                else None
            )
            if tid and tid not in used:
                out["relationships"].append(
                    {
                        "source": subject,
                        "type": "uses",
                        "target": e["mitre_id"],
                        "evidence": e["evidence"],
                    }
                )
    return out


# -- engine 0.4: consolidation by the guidelines' rules ----------------------------

ACTOR = {"intrusion-set", "threat-actor", "campaign"}
SOFTWARE = {"malware", "tool"}
VICTIM = {"sector", "organization", "country", "region"}
# The relationships of gold/GUIDELINES.md: (source types, type, target types).
GUIDELINE_RELATIONSHIPS = [
    (ACTOR | SOFTWARE, "uses", {"attack-pattern"}),
    (ACTOR, "uses", SOFTWARE),
    (ACTOR | {"malware"}, "targets", VICTIM),
    (ACTOR, "targets", {"vulnerability"}),
    ({"malware"}, "exploits", {"vulnerability"}),
    ({"tool"}, "targets", {"vulnerability"}),
    ({"intrusion-set"}, "originates-from", {"country"}),
    ({"threat-actor"}, "located-at", {"country"}),
    ({"intrusion-set"}, "attributed-to", {"threat-actor"}),
    ({"campaign"}, "attributed-to", {"intrusion-set", "threat-actor"}),
    ({"malware"}, "variant-of", {"malware"}),
]
# Not IOCs: the authors' own sites and contacts (guidelines: "the agency's own contacts").
AUTHOR_DOMAINS = re.compile(r"(\.gov|\.mil|\.gouv\.fr|\.gc\.ca|\.gov\.uk|\.gov\.au|mitre\.org)$")


def in_guidelines(r: dict) -> bool:
    s, t = r["source"].get("type"), r["target"].get("type")
    return any(s in a and r["type"] == rt and t in b for a, rt, b in GUIDELINE_RELATIONSHIPS)


def not_an_ioc(o: dict) -> bool:
    v = o["value"].lower()
    if o["type"] in ("ipv4-addr", "ipv6-addr"):
        try:
            return not ipaddress.ip_address(v.split("/")[0]).is_global
        except ValueError:
            return True
    host = v
    if o["type"] == "url":
        host = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    elif o["type"] == "email-addr":
        host = v.split("@")[-1]
    return bool(AUTHOR_DOMAINS.search(host))


def consolidate(
    extraction: dict,
    text: str,
    *,
    guideline_relationships: bool = True,
    drop_non_iocs: bool = True,
    orphan_iocs: bool = True,
) -> dict:
    """The guidelines' rules applied after the model (engine 0.4), on the raw
    lists (entities are left as they are):
    - only the relationships of the guidelines table (the model also writes
      "software uses software", "actor uses CVE"...);
    - not IOCs: private and loopback addresses, the authors' own domains;
    - IOCs tied to nobody indicate the document's main subject (as for
      technique tables: "when the document does not say, the main subject")."""
    ex = compact.parse(extraction)
    resolver = compact.Resolver(ex)
    out = {k: list(extraction.get(k) or []) for k in ("entities", "observables", "relationships")}
    if guideline_relationships:
        kept = []
        for r in out["relationships"]:
            rtype = str(r.get("type") or "").strip().lower()
            src, tgt = compact.pick_ends(resolver, r.get("source"), rtype, r.get("target"))
            if src is None or tgt is None:
                continue
            if compact.reversed_fact(src, rtype, tgt):
                src, tgt = tgt, src
            if in_guidelines({"source": src, "type": rtype, "target": tgt}):
                kept.append(r)
        out["relationships"] = kept
    if drop_non_iocs:
        clean = []
        for o in out["observables"]:
            c = compact.canonical_observable(dict(o))
            if c is not None and not not_an_ioc(c):
                clean.append(o)
        out["observables"] = clean
    subject = main_subject(text, ex.entities)
    if subject and orphan_iocs:
        out["observables"] = [
            o if o.get("indicates") else {**o, "indicates": [subject]} for o in out["observables"]
        ]
    return out
