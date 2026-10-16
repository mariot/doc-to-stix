"""Score a predicted extraction against the gold one.

Matching is by identity, not by spelling: attack-patterns by ATT&CK ID, groups /
software / campaigns by their ATT&CK name when the name is a known alias,
sectors and locations by their OpenCTI name, observables by normalized value,
relationships by (source, type, target) on those identities. Malware and tool
count as one family (the line between them is a judgment call), and so do
intrusion-set and threat-actor.

Per document and over the eval set (counts summed, then precision / recall /
F1): entities (per family too), observables, relationships. The headline is the
mean of the three F1, so a long IOC table does not outweigh the analysis.
"""

from collections import Counter
from dataclasses import dataclass, field

from doc2stix import reference
from doc2stix.compact import Extraction, Resolver, entity_key, family_type, names_of

FAMILY = {
    "intrusion-set": "actors",
    "threat-actor": "actors",
    "campaign": "actors",
    "malware": "software",
    "tool": "software",
    "attack-pattern": "techniques",
    "vulnerability": "vulnerabilities",
    "sector": "victims",
    "organization": "victims",
    "country": "victims",
    "region": "victims",
}
# Relationship types that state the same fact (OpenCTI wants the second).
SAME_FACT = {("actors", "exploits", "vulnerabilities"): "targets"}


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, other: "Counts") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
        }


def compare(gold: set, pred: set) -> Counts:
    return Counts(tp=len(gold & pred), fp=len(pred - gold), fn=len(gold - pred))


@dataclass
class DocScore:
    entities: Counts = field(default_factory=Counts)
    families: dict[str, Counts] = field(default_factory=dict)
    observables: Counts = field(default_factory=Counts)
    relationships: Counts = field(default_factory=Counts)
    missed: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)

    def add(self, other: "DocScore") -> None:
        self.entities.add(other.entities)
        self.observables.add(other.observables)
        self.relationships.add(other.relationships)
        for fam, c in other.families.items():
            self.families.setdefault(fam, Counts()).add(c)

    @property
    def headline(self) -> float:
        return (self.entities.f1 + self.observables.f1 + self.relationships.f1) / 3

    def as_dict(self) -> dict:
        return {
            "headline": round(self.headline, 3),
            "entities": self.entities.as_dict(),
            "families": {k: v.as_dict() for k, v in sorted(self.families.items())},
            "observables": self.observables.as_dict(),
            "relationships": self.relationships.as_dict(),
        }


def gold_index(gold: Extraction) -> dict[tuple, tuple]:
    """(family, name or alias) -> the gold entity's key: a prediction that names
    an entity by an alias the document gives is that entity."""
    idx = {}
    for e in gold.entities:
        for n in names_of(e):
            idx.setdefault((family_type(e["type"]), n), entity_key(e))
    return idx


def top_sector(name: str) -> str:
    """The top-level OpenCTI sector of a sector (Healthcare services -> Health)."""
    parents = {s["name"]: s["parent"] for s in reference.opencti()["sectors"]}
    while parents.get(name):
        name = parents[name]
    return name


def keyer(idx: dict[tuple, tuple]):
    def key(x: dict) -> tuple:
        if "value" in x:
            return Resolver.key(x)
        if x.get("type") == "sector":  # sectors are scored at OpenCTI's top level:
            # "the most specific sector" is a judgment call ("Health" or
            # "Healthcare services" for hospitals); the bundle keeps the specific one
            return ("sector", reference.name_key(top_sector(x["name"])))
        for n in names_of(x):
            hit = idx.get((family_type(x["type"]), n))
            if hit:
                return hit
        return entity_key(x)

    return key


def entity_keys(ex: Extraction, key) -> dict[tuple, str]:
    return {key(e): FAMILY[e["type"]] for e in ex.entities}


def relationship_keys(ex: Extraction, key) -> set[tuple]:
    out = set()
    for r in ex.relationships:
        s, t = key(r["source"]), key(r["target"])
        fs = FAMILY.get(r["source"].get("type"), "observables")
        ft = FAMILY.get(r["target"].get("type"), "observables")
        rtype = SAME_FACT.get((fs, r["type"], ft), r["type"])
        out.add((s, rtype, t))
    resolver = Resolver(ex)
    for o in ex.observables:  # "this IOC belongs to X" is a relationship too
        for name in o.get("indicates", []):
            tgt = resolver.find(name)
            if tgt is not None and "value" not in tgt:
                out.add((key(o), "indicates", key(tgt)))
    return out


def score_document(gold: Extraction, pred: Extraction) -> DocScore:
    ds = DocScore()
    key = keyer(gold_index(gold))
    g, p = entity_keys(gold, key), entity_keys(pred, key)
    ds.entities = compare(set(g), set(p))
    for fam in set(g.values()) | set(p.values()):
        ds.families[fam] = compare(
            {k for k, f in g.items() if f == fam}, {k for k, f in p.items() if f == fam}
        )
    go = {Resolver.key(o) for o in gold.observables}
    po = {Resolver.key(o) for o in pred.observables}
    ds.observables = compare(go, po)
    gr, pr = relationship_keys(gold, key), relationship_keys(pred, key)
    ds.relationships = compare(gr, pr)
    ds.missed = sorted(map(str, (set(g) - set(p)) | (gr - pr)))[:50]
    ds.extra = sorted(map(str, (set(p) - set(g)) | (pr - gr)))[:50]
    return ds


def summarize(scores: dict[str, DocScore]) -> DocScore:
    total = DocScore()
    for s in scores.values():
        total.add(s)
    return total


def family_counts(ex: Extraction) -> Counter:
    return Counter(FAMILY[e["type"]] for e in ex.entities)
