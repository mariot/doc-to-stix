"""Mix the training sources into MLX LoRA data files (train.jsonl, valid.jsonl).

Sources (labels written by people, never by a model):
- attack.jsonl     ATT&CK procedure examples (build_attack_examples.py)
- documents.jsonl  chunks of training advisories labelled with their official
                   STIX files (build_doc_examples.py), repeated --doc-weight times
                   because they are few and closest to the real task

    uv run python training/prepare.py --attack 1200 --doc-weight 4
"""

import argparse
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def load(name: str) -> list[dict]:
    path = DATA / name
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", type=int, default=1200, help="ATT&CK examples to keep")
    ap.add_argument("--doc-weight", type=int, default=4)
    ap.add_argument("--distill", action="store_true", help="add distill.jsonl (v2)")
    ap.add_argument("--valid", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(DATA / "mlx"))
    args = ap.parse_args()
    rng = random.Random(args.seed)
    attack = load("attack.jsonl")
    rng.shuffle(attack)
    attack = attack[: args.attack]
    docs = load("documents.jsonl")
    if args.distill:  # distilled chunks count as documents (held out by document too)
        docs += load("distill.jsonl")
    # validation: whole documents and ATT&CK subjects held out, not copies of training rows
    doc_ids = sorted({d["document"] for d in docs})
    rng.shuffle(doc_ids)
    held_docs = set(doc_ids[: max(1, round(len(doc_ids) * args.valid))])
    n_valid_attack = int(len(attack) * args.valid)
    valid = attack[:n_valid_attack] + [d for d in docs if d["document"] in held_docs]
    train = (
        attack[n_valid_attack:]
        + [d for d in docs if d["document"] not in held_docs] * args.doc_weight
    )
    rng.shuffle(train)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("train", train), ("valid", valid)):
        with (out / f"{name}.jsonl").open("w") as f:
            for r in rows:
                f.write(json.dumps({"messages": r["messages"]}, ensure_ascii=False) + "\n")
    print(
        f"train {len(train)} rows ({len(attack) - n_valid_attack} ATT&CK, "
        f"{len(train) - len(attack) + n_valid_attack} document chunks incl. x{args.doc_weight}); "
        f"valid {len(valid)} (held-out documents: {', '.join(sorted(held_docs))})"
    )


if __name__ == "__main__":
    main()
