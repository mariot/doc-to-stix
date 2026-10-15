"""Fine-tuning examples from MITRE ATT&CK procedure examples (human-written labels).

ATT&CK holds ~19 000 "uses" relationships, each with a sentence written by MITRE
analysts ("[APT29] has used [PowerShell] to ... (Citation: ...)") and a
structured source and target. Grouped by source, a few sentences make a
paragraph; the structured relationships are its labels:

    text   : "APT29 has used encoded PowerShell commands ... APT29 has used Mimikatz ..."
    labels : APT29 (intrusion-set) uses T1059.001, APT29 uses Mimikatz (tool), ...

The model learns the hard part of the task, mapping a described behaviour to an
ATT&CK technique, from labels no model wrote. Relationships citing a document of
the eval split are left out (no eval leak).

    uv run python training/build_attack_examples.py
"""

import json
import random
import re
from collections import defaultdict
from pathlib import Path

import yaml

from doc2stix import prompt, reference

ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "training" / "sources" / "enterprise-attack.json"
OUT = ROOT / "training" / "data" / "attack.jsonl"
TYPE = {
    "intrusion-set": "intrusion-set",
    "malware": "malware",
    "tool": "tool",
    "campaign": "campaign",
}
LINK = re.compile(r"\[([^\]]+)\]\(https?://[^)]+\)")
CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
CODE = re.compile(r"<code>(.*?)</code>")


def plain(text: str) -> str:
    text = LINK.sub(r"\1", text)
    text = CITATION.sub("", text)
    text = CODE.sub(r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def eval_markers() -> list[str]:
    """Strings that identify eval documents in ATT&CK citations (URLs, advisory IDs)."""
    docs = yaml.safe_load((ROOT / "corpus" / "sources.yaml").read_text())["documents"]
    marks = []
    for d in docs:
        if d["split"] != "eval":
            continue
        marks.append(d["url"].lower())
        for m in re.findall(r"aa\d{2}-\d{3}[a-z]|certfr-\d{4}-cti-\d{3}", d["id"].lower()):
            marks.append(m)
    return marks


def ext_id(x: dict) -> str | None:
    for r in x.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def main(seed: int = 7, per_paragraph: tuple[int, int] = (4, 12)) -> None:
    objs = json.loads(ATTACK.read_text())["objects"]
    live = {o["id"]: o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    marks = eval_markers()
    by_source: dict[str, list[dict]] = defaultdict(list)
    leaked = 0
    for r in objs:
        if r["type"] != "relationship" or r["relationship_type"] != "uses":
            continue
        if r.get("revoked") or r.get("x_mitre_deprecated") or not r.get("description"):
            continue
        src, tgt = live.get(r["source_ref"]), live.get(r["target_ref"])
        if not src or not tgt or src["type"] not in TYPE:
            continue
        cites = " ".join(
            f"{x.get('source_name', '')} {x.get('url', '')} {x.get('description', '')}".lower()
            for x in r.get("external_references", [])
        )
        if any(m in cites for m in marks):
            leaked += 1
            continue
        by_source[src["id"]].append(r)
    rng = random.Random(seed)
    examples = []
    for src_id, rels in by_source.items():
        src = live[src_id]
        rng.shuffle(rels)
        i = 0
        while i < len(rels):
            n = rng.randint(*per_paragraph)
            group = rels[i : i + n]
            i += n
            examples.append(example(src, group, live))
    rng.shuffle(examples)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(
        f"{len(examples)} examples from {sum(map(len, by_source.values()))} relationships "
        f"({leaked} left out: they cite an eval document) -> {OUT}"
    )


def example(src: dict, rels: list[dict], live: dict) -> dict:
    sentences = [plain(r["description"]) for r in rels]
    text = " ".join(s if s.endswith(".") else s + "." for s in sentences)
    name = src["name"]
    entities = {name: {"type": TYPE[src["type"]], "name": name, "evidence": sentences[0][:200]}}
    relationships = []
    for r, sentence in zip(rels, sentences, strict=True):
        tgt = live[r["target_ref"]]
        if tgt["type"] == "attack-pattern":
            tid = ext_id(tgt)
            key = tid
            entities.setdefault(
                tid,
                {
                    "type": "attack-pattern",
                    "name": reference.techniques().get(tid, tgt["name"]),
                    "mitre_id": tid,
                    "evidence": sentence[:200],
                },
            )
        elif tgt["type"] in ("malware", "tool"):
            key = tgt["name"]
            entities.setdefault(key, {"type": tgt["type"], "name": key, "evidence": sentence[:200]})
        else:
            continue
        relationships.append(
            {"source": name, "type": "uses", "target": key, "evidence": sentence[:200]}
        )
    answer = {
        "entities": list(entities.values()),
        "observables": [],
        "relationships": relationships,
    }
    user = prompt.user_message(f"Procedure examples: {name}", text, [])
    return {
        "messages": [
            {"role": "system", "content": prompt.SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(answer, ensure_ascii=False)},
        ],
        "source": "attack",
        "subject": name,
    }


if __name__ == "__main__":
    main()
