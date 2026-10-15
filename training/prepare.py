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


def fit(rows: list[dict], max_tokens: int) -> tuple[list[dict], int]:
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained("mlx-community/Qwen3-8B-4bit")
    kept = []
    for r in rows:
        t = tok.apply_chat_template(r["messages"], tokenize=True)
        n = len(t["input_ids"] if hasattr(t, "keys") else t)
        if n <= max_tokens:
            kept.append(r)
    return kept, len(rows) - len(kept)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", type=int, default=1200, help="ATT&CK examples to keep")
    ap.add_argument("--doc-weight", type=int, default=4)
    ap.add_argument("--distill", action="store_true", help="add distill.jsonl (v2)")
    ap.add_argument("--valid", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(DATA / "mlx"))
    ap.add_argument(
        "--max-tokens",
        type=int,
        default=0,
        help="drop rows longer than this (the training max_seq_length): a truncated row teaches "
        "an incomplete answer, and one whose prompt alone fills it has no token to learn from "
        "(loss 0/0: NaN, which poisoned LoRA v2 from its first step)",
    )
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
    if args.max_tokens:
        train, dropped_t = fit(train, args.max_tokens)
        valid, dropped_v = fit(valid, args.max_tokens)
        print(
            f"dropped rows longer than {args.max_tokens} tokens: "
            f"{dropped_t} train, {dropped_v} valid"
        )
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
