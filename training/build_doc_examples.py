"""Fine-tuning examples from training documents and their official STIX files.

CISA and the NCSC publish, with many advisories, a STIX bundle written by the
agency: the indicators, ATT&CK techniques, malware, CVEs and sometimes the
relationships of that document. Those are human labels on real advisory text.

Each training document is cut into the same chunks as at inference; a chunk's
labels are the official objects it contains:
- an indicator whose value appears in the chunk (defanged or not),
- an attack-pattern whose ATT&CK ID appears in the chunk,
- a malware, threat actor or CVE whose name appears in the chunk,
- an official relationship whose two ends are both labels of the chunk, and,
  when the official bundle has one subject (one malware or threat actor), the
  subject "uses" each technique of the chunk.

Official bundles do not list sectors or countries, and prose describes more
than they hold, so only chunks where the labels are dense (IOC tables, technique
tables) are kept: a prose chunk with half its facts unlabeled would teach the
model to leave facts out.

    uv run python training/build_doc_examples.py
"""

import json
import re
from pathlib import Path

import yaml

from doc2stix import compact, extract, prompt, reference
from doc2stix.engine import MAX_CHARS

ROOT = Path(__file__).resolve().parents[1]
IOC_DIR = ROOT / "training" / "sources" / "ioc"
OUT = ROOT / "training" / "data" / "documents.jsonl"
PATTERN_VALUE = re.compile(
    r"\[(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file):(?:value|hashes\.'?([A-Z0-9-]+)'?)"
    r"\s*=\s*'((?:[^'\\]|\\.)*)'\]"
)
MIN_LABELS = 6  # a chunk needs at least this many labels...
MAX_PROSE_LINES = 6  # ...and few long prose lines (tables, not paragraphs)


def official(doc_id: str) -> list[dict]:
    objs = []
    for f in sorted(IOC_DIR.glob(f"{doc_id}__*.json")):
        try:
            b = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(b, dict):
            objs += b.get("objects", [])
    return objs


def mitre_id(o: dict) -> str | None:
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", o.get("name", ""))
    return m.group(0) if m else None


def line_with(chunk: str, needle: str) -> str | None:
    for line in chunk.split("\n"):
        if needle.lower() in compact.refang(line).lower() or needle.lower() in line.lower():
            return line.strip()[:200]
    return None


def chunk_labels(chunk: str, objs: list[dict]) -> dict:
    refanged = compact.refang(chunk).lower()
    low = chunk.lower()
    entities, observables, rels = {}, [], []
    by_id = {}
    for o in objs:
        t = o.get("type")
        if t == "indicator":
            for otype, htype, value in PATTERN_VALUE.findall(o.get("pattern", "")):
                v = value.replace("\\'", "'")
                if v.lower() in refanged or v.lower() in low:
                    item = {"type": otype, "value": v}
                    if otype == "file":
                        item["hash"] = htype.replace("SHA256", "SHA-256").replace("SHA1", "SHA-1")
                    observables.append(item)
                    by_id[o["id"]] = v
        elif t == "attack-pattern":
            tid = mitre_id(o)
            if (
                tid
                and tid in reference.techniques()
                and re.search(rf"\b{re.escape(tid)}(?!\.\d)\b", chunk)
            ):
                entities[tid] = {
                    "type": "attack-pattern",
                    "name": reference.techniques()[tid],
                    "mitre_id": tid,
                    "evidence": line_with(chunk, tid),
                }
                by_id[o["id"]] = tid
        elif t in ("malware", "threat-actor", "intrusion-set", "vulnerability", "tool"):
            name = o.get("name", "")
            if name and re.search(rf"(?<!\w){re.escape(name)}(?!\w)", chunk, re.I):
                etype = {"threat-actor": "intrusion-set"}.get(t, t)
                entities[name] = {"type": etype, "name": name, "evidence": line_with(chunk, name)}
                by_id[o["id"]] = name
    for o in objs:
        if o.get("type") != "relationship":
            continue
        s, g = by_id.get(o.get("source_ref")), by_id.get(o.get("target_ref"))
        if s and g and o.get("relationship_type") in compact.RELATIONSHIP_TYPES | {"indicates"}:
            if o["relationship_type"] == "indicates":
                for ob in observables:
                    if ob["value"] == s:
                        ob.setdefault("indicates", []).append(g)
            else:
                rels.append(
                    {
                        "source": s,
                        "type": o["relationship_type"],
                        "target": g,
                        "evidence": line_with(chunk, g) or line_with(chunk, s),
                    }
                )
    subjects = [
        o["name"] for o in objs if o.get("type") in ("malware", "threat-actor") and o.get("name")
    ]
    if len(set(subjects)) == 1:
        subject = subjects[0]
        for tid, e in list(entities.items()):
            if e["type"] == "attack-pattern":
                rels.append(
                    {"source": subject, "type": "uses", "target": tid, "evidence": e["evidence"]}
                )
        if rels and subject not in entities:
            etype = next(o["type"] for o in objs if o.get("name") == subject)
            entities[subject] = {
                "type": {"threat-actor": "intrusion-set"}.get(etype, etype),
                "name": subject,
                "evidence": None,
            }
    return {
        "entities": list(entities.values()),
        "observables": observables,
        "relationships": [r for r in rels if r["evidence"]],
    }


def main() -> None:
    docs = yaml.safe_load((ROOT / "corpus" / "sources.yaml").read_text())["documents"]
    examples = []
    for d in docs:
        if d["split"] != "train":
            continue
        objs = official(d["id"])
        if not objs:
            continue
        text = (ROOT / "corpus" / "text" / f"{d['id']}.txt").read_text()
        kept = 0
        for chunk in extract.chunks(text, MAX_CHARS):
            labels = chunk_labels(chunk, objs)
            n = len(labels["entities"]) + len(labels["observables"])
            prose = sum(1 for line in chunk.split("\n") if len(line) > 150)
            if n < MIN_LABELS or prose > MAX_PROSE_LINES:
                continue
            # entities named only as relationship subjects need evidence from the chunk
            labels["entities"] = [e for e in labels["entities"] if e["evidence"]]
            names = {e["name"] for e in labels["entities"]} | {
                e.get("mitre_id") for e in labels["entities"]
            }
            labels["relationships"] = [
                r
                for r in labels["relationships"]
                if r["source"] in names | {o["value"] for o in labels["observables"]}
            ]
            for o in labels["observables"]:
                o["indicates"] = [x for x in o.get("indicates", []) if x in names] or None
                if o["indicates"] is None:
                    del o["indicates"]
            user = prompt.user_message(d["title"], chunk, [])
            examples.append(
                {
                    "messages": [
                        {"role": "system", "content": prompt.SYSTEM},
                        {"role": "user", "content": user},
                        {"role": "assistant", "content": json.dumps(labels, ensure_ascii=False)},
                    ],
                    "source": "official-stix",
                    "document": d["id"],
                }
            )
            kept += 1
        print(f"{d['id']:28s} {kept} chunk(s) kept")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"{len(examples)} examples -> {OUT}")


if __name__ == "__main__":
    main()
