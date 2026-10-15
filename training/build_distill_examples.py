"""Fine-tuning examples distilled from an open-weights teacher, with full coverage.

LoRA v1 trained on ATT&CK paragraphs (actors and techniques only) and IOC
tables; it learned to see techniques everywhere and lost sectors, countries and
CVEs. v2 needs examples whose labels cover everything the guidelines ask for,
on real advisory text. Human labels with that coverage do not exist for the
training documents, so:

- teacher: qwen3:30b-a3b (Apache-2.0) with engine 0.2, run on the training
  split with --keep-chunks (each chunk's prompt and answer kept);
- each chunk's label = the teacher's answer + what the chunk writes literally
  (harvest.py) + the official STIX labels of the chunk when the agency
  published a bundle (build_doc_examples.chunk_labels);
- quality filter: an entity or relationship whose evidence is not in the chunk
  and whose name is not either is dropped (the teacher's hallucinations are
  not taught); evidence is re-anchored to the chunk line that names it.

No Claude output is used for training; the eval gold is never used.

    uv run python training/build_distill_examples.py runs/teacher-qwen3-30b-a3b-train
"""

import json
import sys
from pathlib import Path

from doc2stix import compact, extract, harvest, prompt, reference

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "training" / "data" / "distill.jsonl"
sys.path.insert(0, str(ROOT / "training"))
from build_doc_examples import chunk_labels, official  # noqa: E402


def line_naming(chunk: str, name: str) -> str | None:
    low = name.lower()
    for line in chunk.split("\n"):
        if low in line.lower():
            return line.strip()[:200]
    return None


def anchored(chunk: str, squashed: str, evidence: str | None, names: list[str]) -> str | None:
    if evidence and extract.contains_quote(squashed, evidence):
        return evidence[:200]
    for n in names:
        found = line_naming(chunk, n)
        if found:
            return found
    return None


def to_compact(ex: compact.Extraction, chunk: str) -> dict:
    squashed = extract.squash(chunk)
    entities = []
    kept = set()
    for e in ex.entities:
        names = [e["name"], *e.get("aliases", [])] + ([e["mitre_id"]] if e.get("mitre_id") else [])
        if e["type"] not in ("attack-pattern", "sector", "country", "region"):
            # a named entity must be named in this chunk (a real quote about something
            # else does not make it real: the teacher's CVE "evidenced" by a COVID line)
            if not any(extract.squash(n) in squashed for n in names):
                continue
            ev = anchored(chunk, squashed, None, names)
        else:  # described or mapped (techniques in prose, sector words): the quote counts
            ev = anchored(chunk, squashed, e.get("evidence"), names)
        if ev is None:
            continue
        item = {"type": e["type"], "name": e["name"], "evidence": ev}
        if e.get("aliases"):
            item["aliases"] = e["aliases"]
        if e.get("mitre_id"):
            item["mitre_id"] = e["mitre_id"]
        entities.append(item)
        kept.add(id(e))
    solid = extract.squash(compact.refang(chunk)).replace(" ", "")
    observables = []
    for o in ex.observables:
        if o["value"].lower().replace(" ", "") not in solid:
            continue
        item = {"type": o["type"], "value": o["value"]}
        if o.get("hash"):
            item["hash"] = o["hash"]
        if o.get("indicates"):
            item["indicates"] = o["indicates"]
        observables.append(item)
    relationships = []
    for r in ex.relationships:
        s, t = r["source"], r["target"]
        if ("value" not in s and id(s) not in kept) or ("value" not in t and id(t) not in kept):
            continue
        ev = anchored(chunk, squashed, r.get("evidence"), [label(t), label(s)])
        if ev is None:
            continue
        relationships.append(
            {"source": label(s), "type": r["type"], "target": label(t), "evidence": ev}
        )
    return {"entities": entities, "observables": observables, "relationships": relationships}


def label(x: dict) -> str:
    return x.get("value") or x.get("mitre_id") or x["name"]


def main(run_dir: str) -> None:
    examples = []
    for f in sorted(Path(run_dir).glob("*.json")):
        if f.name == "score.json":
            continue
        doc_id = f.stem
        result = json.loads(f.read_text())
        objs = official(doc_id)
        n = 0
        for c in result.get("_chunks", []):
            if c["answer"] is None:
                continue
            merged = {
                k: list(c["answer"].get(k) or [])
                for k in ("entities", "observables", "relationships")
            }
            found = harvest.harvest(c["chunk"])
            merged["entities"] += found["entities"]
            merged["observables"] += found["observables"]
            if objs:
                off = chunk_labels(c["chunk"], objs)
                for k in merged:
                    merged[k] += off[k]
            answer = to_compact(compact.parse(merged), c["chunk"])
            if not any(answer.values()):
                continue
            examples.append(
                {
                    "messages": [
                        {"role": "system", "content": prompt.SYSTEM},
                        {"role": "user", "content": c["user"]},
                        {"role": "assistant", "content": json.dumps(answer, ensure_ascii=False)},
                    ],
                    "source": "distill",
                    "document": doc_id,
                }
            )
            n += 1
        print(f"{doc_id:28s} {n} chunk(s)")
    with OUT.open("w") as fh:
        for ex in examples:
            fh.write(json.dumps(ex, ensure_ascii=False) + "\n")
    kinds = {}
    for ex in examples:
        a = json.loads(ex["messages"][2]["content"])
        for e in a["entities"]:
            kinds[e["type"]] = kinds.get(e["type"], 0) + 1
    print(f"{len(examples)} examples -> {OUT}; entity types: {kinds}")
    assert reference.techniques()  # reference data loaded


if __name__ == "__main__":
    main(sys.argv[1])
