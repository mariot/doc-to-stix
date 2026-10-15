"""doc2stix command line.

doc2stix fetch                      download corpus/sources.yaml, extract text
doc2stix check-gold [ID ...]        evidence, references, STIX build, (--import) OpenCTI
doc2stix build EXTRACTION.json      compact extraction -> STIX bundle
doc2stix run --name N [--split eval]   run the engine on documents -> runs/N/
doc2stix score runs/N [--split eval]   score a run against the gold
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

import yaml

from doc2stix import build, compact, extract, reference
from doc2stix import score as scoring

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "corpus"
GOLD = ROOT / "gold"
RUNS = ROOT / "runs"
UA = "Mozilla/5.0 (doc-to-stix corpus fetcher; research)"


def sources() -> list[dict]:
    return yaml.safe_load((CORPUS / "sources.yaml").read_text())["documents"]


def by_split(split: str | None) -> list[dict]:
    return [d for d in sources() if split in (None, d["split"])]


def doc_path(d: dict) -> Path:
    return CORPUS / "docs" / f"{d['id']}.{d['format']}"


def text_path(d: dict) -> Path:
    return CORPUS / "text" / f"{d['id']}.txt"


def doc_text(d: dict) -> str:
    return text_path(d).read_text()


def cmd_fetch(args) -> int:
    (CORPUS / "docs").mkdir(parents=True, exist_ok=True)
    (CORPUS / "text").mkdir(parents=True, exist_ok=True)
    changed = False
    data = yaml.safe_load((CORPUS / "sources.yaml").read_text())
    for d in data["documents"]:
        path = doc_path(d)
        if not path.exists():
            req = urllib.request.Request(d["url"], headers={"User-Agent": UA})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    path.write_bytes(r.read())
            except Exception as exc:  # noqa: BLE001
                print(f"{d['id']}: download failed: {exc}", file=sys.stderr)
                continue
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if d.get("sha256") and d["sha256"] != sha:
            print(f"{d['id']}: sha256 differs from sources.yaml (document changed upstream)")
        elif not d.get("sha256"):
            d["sha256"] = sha
            changed = True
        if not text_path(d).exists() or args.force:
            text_path(d).write_text(extract.document_text(path))
        print(f"{d['id']}: {len(doc_text(d)):>7} chars")
    if changed:
        (CORPUS / "sources.yaml").write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
        )
    return 0


def load_gold(doc_id: str) -> dict:
    return json.loads((GOLD / f"{doc_id}.json").read_text())


def bundle_for(d: dict, extraction: dict) -> tuple[dict, list[str], compact.Extraction]:
    ex = compact.parse(extraction)
    bundle, dropped = build.build_bundle(
        ex,
        title=d["title"],
        published=build.to_published(str(d["published"])),
        source_url=d["url"],
        author=d["publisher"],
    )
    return bundle, dropped, ex


def check_one(d: dict, gold: dict) -> list[str]:
    """Every problem with one gold file. Empty = the gold is sound."""
    problems = []
    text = doc_text(d)
    squashed = extract.squash(text)
    # IOCs may be defanged, or cut across lines by the PDF layout: compare without whitespace
    # (refang, then remove whitespace, then refang again: "194.33.40\n[\n.\n]104")
    solid = compact.refang(re.sub(r"\s+", "", compact.refang(text))).lower()
    ex = compact.parse(gold)
    problems += [f"parse: {p}" for p in ex.problems]
    for e in gold.get("entities", []):
        ev = e.get("evidence")
        if not ev:
            problems.append(f"entity without evidence: {e.get('type')} {e.get('name')}")
        elif not extract.contains_quote(squashed, ev):
            problems.append(f"evidence not in text: {e.get('name')}: {ev[:80]!r}")
        if e.get("type") == "attack-pattern" and not e.get("mitre_id"):
            problems.append(f"attack-pattern without mitre_id: {e.get('name')}")
        if (
            e.get("type") == "attack-pattern"
            and e.get("mitre_id")
            and not reference.current_technique(e["mitre_id"])
        ):
            problems.append(f"unknown ATT&CK ID {e['mitre_id']} ({e.get('name')})")
    for r in gold.get("relationships", []):
        ev = r.get("evidence")
        if not ev:
            problems.append(f"relationship without evidence: {r}")
        elif not extract.contains_quote(squashed, ev):
            problems.append(
                f"evidence not in text: {r['source']} {r['type']} {r['target']}: {ev[:80]!r}"
            )
    for o in ex.observables:
        if re.sub(r"\s+", "", o["value"]).lower() not in solid:
            problems.append(f"observable not in text: {o['type']} {o['value']}")
    _, dropped, _ = bundle_for(d, gold)
    problems += [f"OpenCTI would refuse: {x}" for x in dropped]
    return problems


def cmd_check_gold(args) -> int:
    docs = [
        d
        for d in sources()
        if (GOLD / f"{d['id']}.json").exists() and (not args.ids or d["id"] in args.ids)
    ]
    api = None
    if args.do_import:
        from doc2stix.opencti import client

        api = client()
    total = 0
    for d in docs:
        gold = load_gold(d["id"])
        problems = check_one(d, gold)
        ex = compact.parse(gold)
        line = (
            f"{d['id']:28s} {len(ex.entities):3d} entities {len(ex.observables):4d} observables "
            f"{len(ex.relationships):3d} relationships"
        )
        if api is not None:
            from doc2stix.opencti import import_and_check

            bundle, _, _ = bundle_for(d, gold)
            c = import_and_check(bundle, api)
            line += f" | OpenCTI {c.summary()}"
            if not c.ok:
                problems += [f"OpenCTI: {e}" for e in c.errors] or ["OpenCTI: objects missing"]
        print(line + ("" if not problems else f"  {len(problems)} PROBLEM(S)"))
        for p in problems[: args.max]:
            print(f"    - {p}")
        total += len(problems)
    print(f"\n{len(docs)} gold files, {total} problem(s)")
    return 1 if total else 0


def cmd_build(args) -> int:
    extraction = json.loads(Path(args.extraction).read_text())
    meta = extraction.get("document") or {}
    ex = compact.parse(extraction)
    bundle, dropped = build.build_bundle(
        ex,
        title=meta.get("title", Path(args.extraction).stem),
        published=build.to_published(meta.get("published", "2026-01-01")),
        source_url=meta.get("url"),
    )
    out = Path(args.output) if args.output else Path(args.extraction).with_suffix(".stix.json")
    out.write_text(build.dumps(bundle))
    for p in ex.problems + dropped:
        print(f"dropped: {p}", file=sys.stderr)
    print(f"{out}: {len(bundle['objects'])} objects")
    return 0


def cmd_score(args) -> int:
    run = Path(args.run)
    docs = [d for d in by_split(args.split) if (GOLD / f"{d['id']}.json").exists()]
    per_doc: dict[str, scoring.DocScore] = {}
    missing = []
    for d in docs:
        pred_path = run / f"{d['id']}.json"
        gold = compact.parse(load_gold(d["id"]))
        if not pred_path.exists():
            missing.append(d["id"])
            pred = compact.Extraction()
        else:
            pred = compact.parse(json.loads(pred_path.read_text()))
        per_doc[d["id"]] = scoring.score_document(gold, pred)
    total = scoring.summarize(per_doc)
    print(f"{run.name} on {len(docs)} {args.split or 'all'} documents")
    print(f"HEADLINE (mean F1)  {total.headline:.3f}")
    for name in ("entities", "observables", "relationships"):
        c = getattr(total, name)
        print(
            f"  {name:14s} P {c.precision:.3f}  R {c.recall:.3f}  F1 {c.f1:.3f}"
            f"   (tp {c.tp}, fp {c.fp}, fn {c.fn})"
        )
    for fam, c in sorted(total.families.items()):
        print(f"    {fam:14s} P {c.precision:.3f}  R {c.recall:.3f}  F1 {c.f1:.3f}")
    print("\nper document (headline, entities F1, relationships F1, observables F1):")
    for doc_id, s in per_doc.items():
        print(
            f"  {doc_id:28s} {s.headline:.3f}  {s.entities.f1:.3f}  {s.relationships.f1:.3f}"
            f"  {s.observables.f1:.3f}"
        )
    if missing:
        print(f"\nMISSING predictions ({len(missing)}, scored as empty): {', '.join(missing)}")
    report = {
        "run": run.name,
        "split": args.split,
        "total": total.as_dict(),
        "documents": {
            k: {**v.as_dict(), "missed": v.missed, "extra": v.extra} for k, v in per_doc.items()
        },
    }
    (run / "score.json").write_text(json.dumps(report, indent=1, ensure_ascii=False))
    return 0


def cmd_run(args) -> int:
    from doc2stix.engine import Engine

    engine = Engine.from_args(args)
    out = RUNS / args.name
    out.mkdir(parents=True, exist_ok=True)
    docs = by_split(args.split)
    if args.ids:
        docs = [d for d in docs if d["id"] in args.ids.split(",")]
    for i, d in enumerate(docs, 1):
        target = out / f"{d['id']}.json"
        if target.exists() and not args.force:
            continue
        result = engine.extract(doc_text(d), title=d["title"])
        target.write_text(json.dumps(result, ensure_ascii=False, indent=1))
        meta = result.get("_meta", {})
        print(
            f"[{i}/{len(docs)}] {d['id']:28s} {len(result.get('entities', [])):3d} entities "
            f"{len(result.get('relationships', [])):3d} rels {meta.get('seconds', 0):6.0f}s "
            f"{meta.get('errors', '')}",
            flush=True,
        )
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="doc2stix")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("fetch")
    p.add_argument("--force", action="store_true", help="re-extract the text")
    p.set_defaults(func=cmd_fetch)
    p = sub.add_parser("check-gold")
    p.add_argument("ids", nargs="*")
    p.add_argument("--import", dest="do_import", action="store_true")
    p.add_argument("--max", type=int, default=15)
    p.set_defaults(func=cmd_check_gold)
    p = sub.add_parser("build")
    p.add_argument("extraction")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_build)
    p = sub.add_parser("score")
    p.add_argument("run")
    p.add_argument("--split", default="eval")
    p.set_defaults(func=cmd_score)
    p = sub.add_parser("run")
    p.add_argument("--name", required=True)
    p.add_argument("--split", default="eval")
    p.add_argument("--ids")
    p.add_argument("--force", action="store_true")
    p.add_argument("--model", default="qwen3:30b-a3b")
    p.add_argument("--base-url", default="http://localhost:11434")
    p.add_argument("--adapter", help="MLX LoRA adapter directory (fine-tuned model)")
    p.add_argument("--no-harvest", action="store_true", help="model only (engine 0.1 behaviour)")
    p.add_argument("--keep-chunks", action="store_true", help="keep each chunk's answer")
    p.set_defaults(func=cmd_run)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
