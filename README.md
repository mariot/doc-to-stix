# doc-to-stix

Threat-intelligence documents (PDF, HTML, text) to **coherent STIX 2.1 bundles
that OpenCTI imports as they are**: intrusion sets, threat actors, campaigns,
malware, tools, MITRE ATT&CK techniques, CVEs, targeted sectors and countries,
indicators and observables, and the relationships between them.

It is the engine of an OpenCTI enrichment connector
([opencti-connector-doc-to-stix](https://github.com/mariot/opencti-connector-doc-to-stix)):
pick an entity that has a document attached, the connector reads the document
and enriches the entity with what it says.

Same method as [dvf-text-to-sql](https://github.com/mariot/dvf-text-to-sql-eval):
a gold set first, then the engine, then training, each change scored.

```
document ─► text (PDFium) ─► chunks ─► model ─► compact JSON ─► checks ─► STIX 2.1 bundle ─► OpenCTI
                                        ▲          (entities,     (OpenCTI names,   (deterministic IDs,
                     rules (prompt.py) ─┘           observables,   ATT&CK IDs,       allowed relationships
                                                    relationships) evidence)         only, one Report)
```

## Design

- **The model never writes STIX.** It writes a small JSON (`compact.py`): entities
  with an evidence quote, observables, relationships between names. A
  deterministic builder (`build.py`) makes the STIX: OpenCTI's deterministic IDs
  (pycti `generate_id`, so the same malware from two reports is one object),
  an indicator with its STIX pattern for every observable, and **only the
  relationships OpenCTI accepts** between those two entity types (the 92-pair
  table of `stixCoreRelationshipsMapping`, `data/opencti_relationships.json`).
  A bundle cannot be refused for a bad relationship; a fact OpenCTI records
  differently is converted ("an actor exploits a CVE" → *targets*).
- **OpenCTI's own names.** Sectors, countries and regions are mapped to the
  names of OpenCTI's reference datasets (`data/opencti_reference.json`, with
  common synonyms: CISA's 16 critical-infrastructure sectors, "United States",
  French names), so they merge with the objects every OpenCTI already has.
- **ATT&CK as reference.** Enterprise, Mobile and ICS v20, with the 210
  revoked or renumbered IDs mapped to the current ones (documents cite the
  ATT&CK of their date: T1562.001 is T1685 since v20).
- **Usable is measured, not assumed:** `doc2stix check-gold --import` sends
  every bundle to a local OpenCTI (`infra/opencti`, OpenCTI 7.261008.0) and
  checks that every object is in the report afterwards.

### What OpenCTI does with a bundle (measured on the 22 gold bundles)

`doc2stix check-gold --import` imports each gold bundle the way OpenCTI's
workers do (split in dependency order) and reads the report back. All 22
import without error: **every entity and every relationship exists in
OpenCTI afterwards** (1 271 + 854 objects, 1 416 relationships). Two platform
behaviours cost the *report* some of its links, not the facts:

- **Existing relationships.** When a relationship with the same type and ends
  already exists (ATT&CK's own "Star Blizzard uses T1589", loaded by the MITRE
  connector), OpenCTI merges the incoming one into it without recording the
  incoming ID, and the report's reference to that ID is dropped: Star Blizzard
  keeps 14 of its 26 relationships in the report, all 26 exist. The connector
  works around it by also referencing the existing relationship.
- **Alias resolution.** An incoming entity whose name is an alias of an
  existing one is merged into it ("UNC1878" lands on FIN12, "GIFTEDVISITOR" on
  WIREFIRE), even when the document keeps them apart; 2 entities of 1 271.

## The gold set

22 documents of the eval split (`corpus/sources.yaml`), annotated by the rules
of [`gold/GUIDELINES.md`](gold/GUIDELINES.md): 1 271 entities, 854 observables,
1 416 relationships. Every entity and relationship carries a quote of the
document; `doc2stix check-gold` verifies that each quote is in the text, each
IOC is in the text (defanged, or cut across lines by the PDF), each ATT&CK ID
exists, and that OpenCTI would accept every relationship.

| | |
|---|---|
| Sources | CISA joint advisories, CERT-FR (ANSSI) reports (French and English), UK NCSC malware analysis reports and advisories |
| Topics | China, Russia, Iran, North Korea espionage; ransomware (Akira, CL0P, Medusa, Ryuk, FIN12); CVE exploitation (Citrix, Ivanti, SimpleHelp); Scattered Spider; pro-Russia hacktivists; malware analysis |
| Split | 22 eval documents (gold, never trained on), 42 training documents |

The gold was drafted with an LLM (Claude), each file by an agent following the
guidelines, then machine-checked (above) and revised in a second pass when the
checks or rules changed. It is the reference the models are scored against;
**it is never used for training** (see Training data).

Documents: only works of US federal agencies alone (public domain) are
committed; for the others `corpus/sources.yaml` holds the URL and SHA-256 and
`doc2stix fetch` downloads them.

## Scoring

`doc2stix score runs/<name>`: precision, recall and F1 over the eval set
(counts summed over documents) for entities (and per family: actors, software,
techniques, vulnerabilities, victims), observables and relationships. The
headline is the mean of the three F1, so a long IOC table does not outweigh the
analysis. Matching is by identity: ATT&CK techniques by current ID, other
entities by name with spacing and punctuation ignored or by an alias the
document gives; malware/tool and intrusion-set/threat-actor are one family each.

## Training data

Labels written by people, never by a model:

- **ATT&CK procedure examples** (`training/build_attack_examples.py`): 18 796
  "uses" relationships with the sentence MITRE analysts wrote for each
  ("APT29 has used encoded PowerShell commands…"), grouped into 2 856
  paragraphs; the structured relationships are the labels. It teaches the hard
  part, mapping a described behaviour to an ATT&CK technique. Relationships
  citing an eval document are left out (174).
- **Official STIX files** (`training/build_doc_examples.py`): CISA and the NCSC
  publish, with many advisories, a STIX bundle they wrote for that document
  (indicators, techniques, malware, CVEs, relationships). Chunks of the
  training documents where those labels are dense (IOC and technique tables)
  become examples: 49 chunks, 1 393 IOCs, 589 entities.

## Commands

```
uv sync --all-groups
uv run doc2stix fetch                       # download the corpus, extract the text
uv run doc2stix check-gold [--import]       # check the gold (and import it into OpenCTI)
uv run doc2stix run --name N --model M      # run the engine on the eval documents -> runs/N/
uv run doc2stix score runs/N                # score a run
uv run doc2stix build extraction.json       # compact extraction -> STIX bundle
cd infra/opencti && cp .env.example .env && ./make-secrets.sh && docker compose up -d
```

## Results

Engine versions in `src/doc2stix/__init__.py`; runs and scores in `runs/`.

| run | model | headline | entities F1 | relationships F1 | observables F1 |
|---|---|---|---|---|---|
| **qwen3-30b-a3b-e0.2** | **qwen3:30b-a3b, engine 0.2** | **0.695** | **0.820** | **0.390** | **0.876** |
| doc2stix-qwen3-8b-v1-e0.2 | LoRA v1 (Qwen3-8B), engine 0.2 | 0.579 | 0.654 | 0.179 | 0.904 |
| harvest-only | no model, harvesting only | 0.531 | 0.698 | 0.000 | 0.894 |
| qwen3-30b-a3b-e0.1 | qwen3:30b-a3b, engine 0.1 | 0.460 | 0.645 | 0.299 | 0.437 |
| qwen3-8b-e0.1 | qwen3:8b untrained, engine 0.1 | 0.352 | 0.398 | 0.115 | 0.544 |
| doc2stix-qwen3-8b-v1-e0.1 | LoRA v1 (Qwen3-8B), engine 0.1 | 0.245 | 0.419 | 0.002 | 0.313 |

Per family (F1), engine 0.2 with qwen3:30b-a3b: actors 0.64, software 0.70,
techniques 0.91, victims 0.53, vulnerabilities 0.96. The weak spots are
relationships (precision 0.56, recall 0.30) and victims (recall 0.45).

## Training log

Every step taken to improve the training, in order, with its effect.

1. **Baseline (engine 0.1).** qwen3:30b-a3b through Ollama, chunks of 9 000
   characters, the rules in the system prompt, entities found so far passed to
   the next chunk. First finding: qwen3 answers in prose (reasoning written out,
   even with thinking off) and runs out of tokens before any JSON; **Ollama's
   JSON-schema constrained decoding** fixed it (24 s for a paragraph, valid
   JSON every time).
2. **Normalization shared by gold and predictions.** The first outputs used
   CISA sector names ("Transportation Systems"), labelled hashes ("SHA256
   e3b0…") and reversed relationships ("China originates-from Volt Typhoon"):
   sector synonyms, hash clean-up and direction repair were added to the
   parser, so neither the gold nor a model is penalised for them.
3. **ATT&CK versions.** The gold annotators found documents citing techniques
   that ATT&CK v20 revoked or renumbered, and Mobile/ICS techniques; the
   reference now has all three domains and maps 210 old IDs to current ones.
4. **No merging through ATT&CK alias lists.** ATT&CK lists FIN12 and UNC1878
   as aliases of Wizard Spider; reports keep them apart. Entities now merge
   only through aliases the document itself gives.
5. **Training data from human labels only** (above): 1 140 ATT&CK paragraphs +
   49 official-STIX chunks ×4, 2.8 M tokens; 69 held out for validation
   (including one whole document).
6. **Baseline scored: 0.440** (entities F1 0.64, observables 0.44,
   relationships 0.24). Techniques: precision 0.98 but recall 0.41: long
   ATT&CK tables are skipped; 13 chunks in 8 documents gave unparsable JSON
   (answers cut at the output limit on IOC tables).
7. **Matching fixes in the scorer** (applied to every run): generic suffixes do
   not make another entity ("DragonForce Ransomware" = "DragonForce", "Akira
   threat actors" = "Akira"), and when a name fits two entities (the CL0P
   malware, the CL0P group) a relationship takes the pair OpenCTI accepts.
   Baseline rescored: **0.460** (relationships 0.30).
8. **Harvesting (engine 0.2): 0.460 → 0.695** with qwen3:30b-a3b (techniques
   F1 0.58 → 0.91, observables 0.44 → 0.88, relationships 0.30 → 0.39; on the
   APT40 advisory 0.53 → 0.95). ATT&CK IDs, CVE IDs, hashes, defanged IOCs and
   public IPs written literally are added to the model's extraction; techniques
   nobody uses go to the document's main subject. Harvesting alone, without a
   model, scores 0.531 (techniques F1 0.91, CVEs 0.96, observables 0.89, no
   relationships): the model's job is what needs reading.
9. **LoRA v1**: Qwen3-8B (4-bit MLX), 16 layers, prompt masked, one epoch
   (1 300 steps, 4 h 30 at ~150 tokens/s on an M4 Pro), lr 1e-4, sequences up
   to 6 144 tokens. Training loss 0.10 → 0.03; validation loss mostly NaN (the
   held-out document's IOC-table chunks are longer than 6 144 tokens: nothing
   left to score after truncation). Fused (dequantized) and imported into
   Ollama (`-q int4`: this Ollama accepts int4/int8/nvfp4/mxfp4/mxfp8, not
   q4_K_M). Models imported from safetensors have **no structured output** in
   Ollama: the engine falls back to free output for them.
   **Result: the model narrowed.** On a test paragraph it extracts only
   techniques (inventing some: "Target Sector: Energy"), calls Volt Typhoon a
   campaign, and drops the CVE, the sector, the country and the tools: 88 % of
   its examples were ATT&CK paragraphs, which hold only actors and techniques.
   Scored on the eval set: **0.245 against 0.352 for the untrained qwen3:8b**
   (engine 0.1). Techniques improved (F1 0.34 → 0.60), everything else
   collapsed: relationships 0.12 → 0.002, software 0.44 → 0.01, victims
   0.38 → 0.06; 21 chunks unparsable (free output, no schema). With
   harvesting (engine 0.2) it reaches 0.579, below the 30B's 0.695.
   Lesson: examples whose labels cover only part of the task teach the model
   to leave the rest out.
10. **Unparsable chunks found: engine 0.3.** Every run lost chunks (13 in the
    30B's engine 0.2 run): the answer for a long IOC table hits the 6 000-token
    output limit and the JSON is cut, or the model loops and Ollama aborts it
    ("token repeat limit reached", which also stopped the qwen3:8b run at
    document 18). Engine 0.3 asks again in two halves of the chunk (down to two
    levels), and a failed request no longer ends the document.
11. **LoRA v2: distillation for coverage.** Labels with full coverage on real
    advisory text: the open-weights teacher (qwen3:30b-a3b, Apache-2.0, engine
    0.2) extracts the 42 training documents chunk by chunk; each chunk's label
    = the teacher's answer + the chunk's literal IDs and IOCs + the official
    STIX labels, filtered (a named entity must be named in the chunk; evidence
    re-anchored to the chunk). Mixed with 250 ATT&CK paragraphs (down from
    1 140) and the official-STIX chunks ×2; lr 5e-5. The best the student can
    do is match the teacher, at a third of its memory.

## License and data

Code: Apache-2.0 (`LICENSE`). Data included or derived:

- **MITRE ATT&CK®** (`src/doc2stix/data/attack_reference.json`, training
  examples): © The MITRE Corporation. This work is reproduced and distributed
  with the permission of The MITRE Corporation
  ([terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)).
- **OpenCTI datasets** (`src/doc2stix/data/opencti_reference.json`) and the
  relationship table of OpenCTI (`opencti_relationships.json`): Filigran,
  Apache-2.0.
- **Documents**: only advisories written by US federal agencies alone are in
  `corpus/` (public domain, 17 U.S.C. § 105). The others (joint advisories with
  foreign agencies, CERT-FR under Licence Ouverte, UK NCSC under the Open
  Government Licence) are referenced by URL and SHA-256 and fetched with
  `doc2stix fetch`. The gold files quote short passages of each document as
  evidence.
