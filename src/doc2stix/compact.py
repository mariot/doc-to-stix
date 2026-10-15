"""The compact extraction format: what the gold holds and what the model writes.

The model never writes STIX. It lists what the document says, in a small JSON
that is easy to generate and to fine-tune on; build.py turns it into a STIX 2.1
bundle with OpenCTI's deterministic IDs and only the relationships OpenCTI
accepts.

    {
      "entities": [
        {"type": "intrusion-set", "name": "Volt Typhoon", "aliases": ["BRONZE SILHOUETTE"],
         "evidence": "a quote from the document"},
        {"type": "attack-pattern", "name": "PowerShell", "mitre_id": "T1059.001"},
        {"type": "vulnerability", "name": "CVE-2023-27997"},
        {"type": "sector", "name": "Energy"},
        {"type": "country", "name": "United States"}
      ],
      "observables": [
        {"type": "ipv4-addr", "value": "203.0.113.5", "indicates": ["Volt Typhoon"]},
        {"type": "file", "value": "<sha256>", "hash": "SHA-256"}
      ],
      "relationships": [
        {"source": "Volt Typhoon", "type": "uses", "target": "T1059.001",
         "evidence": "a quote from the document"}
      ]
    }

Relationships name their ends: an entity by its name (or an alias), an
attack-pattern by its ATT&CK ID or name, an observable by its value.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from doc2stix import reference

ENTITY_TYPES = {
    "intrusion-set",  # a named group of activity (APT29, Volt Typhoon, LockBit affiliates)
    "threat-actor",  # a real-world actor behind intrusion sets (a state service, a person)
    "campaign",
    "malware",
    "tool",  # legitimate or dual-use software (Mimikatz, PsExec, AnyDesk)
    "attack-pattern",
    "vulnerability",
    "sector",
    "organization",
    "country",
    "region",
}
OBSERVABLE_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file"}
HASH_TYPES = {"MD5", "SHA-1", "SHA-256", "SHA-512"}
HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
RELATIONSHIP_TYPES = {
    "uses",
    "targets",
    "attributed-to",
    "exploits",
    "originates-from",
    "located-at",
    "variant-of",
    "related-to",
}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")  # Enterprise and Mobile T1xxx, ICS T0xxx


def refang(value: str) -> str:
    """hxxp://evil[.]com -> http://evil.com: reports defang IOCs so nobody clicks them."""
    v = value.strip().strip("<>\"'`")
    v = re.sub(r"\bhxxp", "http", v, flags=re.I)  # anywhere: also used on whole documents
    v = re.sub(r"\bfxp", "ftp", v, flags=re.I)
    for a, b in (
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[dot]", "."),
        ("(dot)", "."),
        ("[]", ""),
    ):
        v = v.replace(a, b)
    v = v.replace("[:]", ":").replace("[://]", "://").replace("[@]", "@").replace("[at]", "@")
    return v


def normalize_observable(otype: str, value: str) -> str:
    v = refang(value)
    if otype == "domain-name":
        return v.lower().rstrip(".")
    if otype == "email-addr":
        return v.lower()
    if otype in ("ipv4-addr", "ipv6-addr"):
        try:
            return str(ipaddress.ip_interface(v)).removesuffix("/32").removesuffix("/128")
        except ValueError:
            return v
    if otype == "file":
        return v.lower()
    return v  # url: case matters in the path


@dataclass
class Extraction:
    entities: list[dict] = field(default_factory=list)
    observables: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def canonical_entity(e: dict) -> dict | None:
    """Clean one entity, or None (with the reason in e['_problem']) if it can't be used.

    Sectors, countries and regions take OpenCTI's names; attack-patterns take the
    ATT&CK ID and name; vulnerabilities an upper-case CVE ID.
    """
    t, name = e.get("type"), str(e.get("name") or "").strip()
    if t not in ENTITY_TYPES or not name:
        e["_problem"] = f"unknown entity type {t!r} or empty name"
        return None
    out = {"type": t, "name": name}
    aliases = [a.strip() for a in e.get("aliases") or [] if a and a.strip() and a.strip() != name]
    if aliases:
        out["aliases"] = sorted(set(aliases))
    if t == "attack-pattern":
        # documents cite IDs of their ATT&CK version: revoked IDs map to the current one
        tid = str(e.get("mitre_id") or "").strip().upper() or None
        tid = reference.current_technique(tid) if tid and MITRE_ID.match(tid) else None
        if not tid:
            tid = reference.technique_by_name().get(reference.norm(name))
        if tid:
            out["mitre_id"] = tid
            out["name"] = reference.techniques()[tid]
    elif t == "vulnerability":
        cve = name.upper().replace("–", "-")
        if not CVE.match(cve):
            e["_problem"] = f"vulnerability {name!r} is not a CVE ID"
            return None
        out["name"] = cve
    elif t == "sector":
        known = reference.sector(name)
        if not known:
            e["_problem"] = f"sector {name!r} is not an OpenCTI sector"
            return None
        out["name"] = known
    elif t == "country":
        known = reference.country(name)
        if not known:
            e["_problem"] = f"country {name!r} is not an OpenCTI country"
            return None
        out["name"] = known
    elif t == "region":
        known = reference.region(name)
        if not known:
            e["_problem"] = f"region {name!r} is not an OpenCTI region"
            return None
        out["name"] = known
    if e.get("evidence"):
        out["evidence"] = str(e["evidence"]).strip()
    return out


def canonical_observable(o: dict) -> dict | None:
    t, value = o.get("type"), str(o.get("value") or "").strip()
    if t not in OBSERVABLE_TYPES or not value:
        o["_problem"] = f"unknown observable type {t!r} or empty value"
        return None
    v = normalize_observable(t, value)
    out = {"type": t, "value": v}
    if t == "file":
        # "SHA256 e3b0...", "MD5: 9e10...": keep the hex value
        hexes = re.findall(r"\b[0-9a-f]{32,128}\b", v)
        v = max(hexes, key=len) if hexes else v
        out["value"] = v
        h = str(o.get("hash") or "").upper().replace("SHA256", "SHA-256").replace("SHA1", "SHA-1")
        h = h if h in HASH_TYPES else HASH_LENGTHS.get(len(v))
        if not h or not re.fullmatch(r"[0-9a-f]+", v):
            o["_problem"] = f"file observable {value!r} is not a hash"
            return None
        out["hash"] = h
    elif t == "ipv4-addr":
        try:
            ipaddress.IPv4Interface(v)
        except ValueError:
            o["_problem"] = f"{value!r} is not an IPv4 address"
            return None
    elif t == "domain-name" and ("." not in v or "/" in v or " " in v):
        o["_problem"] = f"{value!r} is not a domain name"
        return None
    indicates = [str(x).strip() for x in o.get("indicates") or [] if str(x).strip()]
    if indicates:
        out["indicates"] = sorted(set(indicates))
    return out


def parse(data: dict) -> Extraction:
    """Clean a compact extraction (gold or model output); duplicates are merged and
    every dropped item leaves a problem message."""
    ex = Extraction()
    seen: dict[tuple, dict] = {}  # every (family, name or alias) -> its entity
    for e in data.get("entities") or []:
        e = dict(e)
        c = canonical_entity(e)
        if c is None:
            ex.problems.append(e.get("_problem") or f"bad entity {e}")
            continue
        keys = [(family_type(c["type"]), k) for k in names_of(c)]
        prev = next((seen[k] for k in keys if k in seen), None)
        if prev is not None:  # the same entity again (by name or by an alias the document gives)
            merged = set(prev.get("aliases", [])) | set(c.get("aliases", [])) | {c["name"]}
            merged.discard(prev["name"])
            if merged:
                prev["aliases"] = sorted(merged)
            for k in keys:
                seen.setdefault(k, prev)
            continue
        for k in keys:
            seen[k] = c
        ex.entities.append(c)
    obs_seen: set[tuple] = set()
    for o in data.get("observables") or []:
        o = dict(o)
        c = canonical_observable(o)
        if c is None:
            ex.problems.append(o.get("_problem") or f"bad observable {o}")
            continue
        if (c["type"], c["value"]) in obs_seen:
            continue
        obs_seen.add((c["type"], c["value"]))
        ex.observables.append(c)
    resolver = Resolver(ex)
    rel_seen: set[tuple] = set()
    for r in data.get("relationships") or []:
        rtype = str(r.get("type") or "").strip().lower()
        src, tgt = pick_ends(resolver, r.get("source"), rtype, r.get("target"))
        if rtype not in RELATIONSHIP_TYPES or src is None or tgt is None:
            ex.problems.append(f"unresolved relationship {r}")
            continue
        if reversed_fact(src, rtype, tgt):  # "China originates-from Volt Typhoon"
            src, tgt = tgt, src
        rtype = REMAP.get((opencti_type(src), rtype, opencti_type(tgt)), rtype)
        key = (resolver.key(src), rtype, resolver.key(tgt))
        if key in rel_seen or key[0] == key[2]:
            continue
        rel_seen.add(key)
        rel = {"source": src, "type": rtype, "target": tgt}
        if r.get("evidence"):
            rel["evidence"] = str(r["evidence"]).strip()
        ex.relationships.append(rel)
    return ex


OPENCTI_TYPE = {
    "intrusion-set": "Intrusion-Set",
    "threat-actor": "Threat-Actor-Group",
    "campaign": "Campaign",
    "malware": "Malware",
    "tool": "Tool",
    "attack-pattern": "Attack-Pattern",
    "vulnerability": "Vulnerability",
    "sector": "Sector",
    "organization": "Organization",
    "country": "Country",
    "region": "Region",
}


# Facts OpenCTI records with another relationship type: an actor "exploits" a CVE
# in reports, OpenCTI says it "targets" it; a threat actor (a state agency) is
# "located-at" its country, "originates-from" is for intrusion sets.
REMAP = {
    ("Intrusion-Set", "exploits", "Vulnerability"): "targets",
    ("Threat-Actor-Group", "exploits", "Vulnerability"): "targets",
    ("Campaign", "exploits", "Vulnerability"): "targets",
    ("Tool", "exploits", "Vulnerability"): "targets",
    ("Threat-Actor-Group", "originates-from", "Country"): "located-at",
    ("Threat-Actor-Group", "originates-from", "Region"): "located-at",
}


def opencti_type(x: dict) -> str:
    return "Observable" if "value" in x else OPENCTI_TYPE[x["type"]]


def pick_ends(resolver, src_ref, rtype: str, tgt_ref) -> tuple[dict | None, dict | None]:
    """The two ends a relationship names; when a name fits several entities, the
    pair OpenCTI accepts for this relationship type (either direction)."""
    srcs, tgts = resolver.find_all(src_ref), resolver.find_all(tgt_ref)
    if not srcs or not tgts:
        return (srcs[0] if srcs else None), (tgts[0] if tgts else None)
    allowed = reference.allowed_relationships()
    for s in srcs:
        for t in tgts:
            a, b = opencti_type(s), opencti_type(t)
            fact = REMAP.get((a, rtype, b), rtype)
            if fact in allowed.get(f"{a}|{b}", []) or rtype in allowed.get(f"{b}|{a}", []):
                return s, t
    return srcs[0], tgts[0]


def reversed_fact(src: dict, rtype: str, tgt: dict) -> bool:
    """True when OpenCTI refuses this direction but accepts the other one."""
    allowed = reference.allowed_relationships()
    forward = f"{opencti_type(src)}|{opencti_type(tgt)}"
    backward = f"{opencti_type(tgt)}|{opencti_type(src)}"
    return rtype not in allowed.get(forward, []) and rtype in allowed.get(backward, [])


def family_type(t: str) -> str:
    """Types that are one family for identity: an actor named in a report may be an
    intrusion-set or a threat-actor, a program malware or a tool (judgment calls)."""
    return {"threat-actor": "intrusion-set", "tool": "malware"}.get(t, t)


def names_of(e: dict) -> list[str]:
    if e["type"] == "attack-pattern" and e.get("mitre_id"):
        return [e["mitre_id"]]
    return [reference.name_key(n) for n in [e["name"], *e.get("aliases", [])]]


def entity_key(e: dict) -> tuple[str, str]:
    """Identity of an entity: attack-patterns by ATT&CK ID, everything else by its
    name (spacing and punctuation ignored). Aliases are matched where the document
    gives them (parse, score), never through ATT&CK's alias lists: those merge
    groups that reports keep apart (FIN12, UNC1878 and Wizard Spider)."""
    return (family_type(e["type"]), names_of(e)[0])


class Resolver:
    """Finds what a relationship end names: an entity name or alias, an ATT&CK ID,
    or an observable value."""

    def __init__(self, ex: Extraction):
        self.by_name: dict[str, dict] = {}
        self.all_by_name: dict[str, list[dict]] = {}  # a name may fit several entities
        for e in ex.entities:
            for n in [e["name"], *e.get("aliases", [])]:
                self.by_name.setdefault(reference.name_key(n), e)
                same = self.all_by_name.setdefault(reference.name_key(n), [])
                if e not in same:
                    same.append(e)
            if e.get("mitre_id"):
                self.by_name.setdefault(reference.name_key(e["mitre_id"]), e)
                for old, new in reference.revoked().items():  # a relationship may cite an old ID
                    if new == e["mitre_id"]:
                        self.by_name.setdefault(reference.name_key(old), e)
        for e in ex.entities:  # ATT&CK aliases last, only to resolve a relationship end
            canon = reference.canonical_names().get(reference.norm(e["name"]))
            if canon:
                self.by_name.setdefault(reference.name_key(canon), e)
        self.by_value: dict[str, dict] = {}
        for o in ex.observables:
            self.by_value.setdefault(o["value"].lower(), o)

    def find_all(self, ref) -> list[dict]:
        """Every entity the name may mean ("CL0P": the malware, "CL0P Ransomware
        Gang": the group), the one written exactly like it first."""
        if not ref:
            return []
        ref = str(ref).strip()
        found = self.all_by_name.get(reference.name_key(ref), [])
        if len(found) > 1:
            exact = reference.norm(ref)
            return sorted(found, key=lambda e: reference.norm(e["name"]) != exact)
        one = self.find(ref)
        return [one] if one else []

    def find(self, ref) -> dict | None:
        if not ref:
            return None
        ref = str(ref).strip()
        hit = self.by_name.get(reference.name_key(ref))
        if hit:
            return hit
        for t in ("url", "domain-name", "ipv4-addr", "file"):
            hit = self.by_value.get(normalize_observable(t, ref).lower())
            if hit:
                return hit
        # the OpenCTI name of a country, region or sector ("United States" ->
        # "United States of America"), then the ATT&CK name of an alias
        for canon in (
            reference.country(ref),
            reference.region(ref),
            reference.sector(ref),
            reference.canonical_names().get(reference.norm(ref)),
        ):
            if canon and reference.name_key(canon) in self.by_name:
                return self.by_name[reference.name_key(canon)]
        return None

    @staticmethod
    def key(x: dict) -> tuple[str, str]:
        if "value" in x:
            return (x["type"], x["value"].lower())
        return entity_key(x)
