import json
from pathlib import Path

import stix2

from doc2stix import harvest, reference
from doc2stix.build import build_bundle
from doc2stix.compact import parse, refang
from doc2stix.score import score_document

SAMPLE = json.loads((Path(__file__).parent / "fixtures" / "sample_extraction.json").read_text())


def test_refang_anywhere_and_odd_forms():
    assert refang("hxxps://evil[.]example[.]com/a") == "https://evil.example.com/a"
    assert refang("see hxxp://x[.]io") == "see http://x.io"
    assert refang("fortigate.forticloud.[]online") == "fortigate.forticloud.online"


def test_names_map_to_opencti_reference():
    assert reference.country("USA") == "United States of America"
    assert reference.country("Russia") == "Russian Federation"
    assert (
        reference.sector("Water and Wastewater Systems sector") == "Water distribution and supply"
    )
    assert reference.sector("Spaceships") is None


def test_revoked_attack_ids_map_to_current():
    assert reference.current_technique("T1562.001") == "T1685"
    assert reference.current_technique("T1059.001") == "T1059.001"
    assert reference.current_technique("T0883")  # ICS
    assert reference.current_technique("T9999") is None


def test_parse_merges_by_document_aliases_not_attack_aliases():
    ex = parse(
        {
            "entities": [
                {"type": "intrusion-set", "name": "APT 29", "aliases": ["Cozy Bear"]},
                {"type": "intrusion-set", "name": "Cozy Bear"},  # alias given by the document
                {"type": "intrusion-set", "name": "FIN12"},
                {
                    "type": "intrusion-set",
                    "name": "Wizard Spider",
                },  # ATT&CK alias of FIN12: kept apart
            ]
        }
    )
    assert [e["name"] for e in ex.entities] == ["APT 29", "FIN12", "Wizard Spider"]


def test_relationship_repairs():
    ex = parse(
        {
            "entities": [
                {"type": "intrusion-set", "name": "Volt Typhoon"},
                {"type": "country", "name": "China"},
                {"type": "threat-actor", "name": "MSS"},
                {"type": "tool", "name": "Through the Wire"},
                {"type": "vulnerability", "name": "CVE-2022-26134"},
            ],
            "relationships": [
                {"source": "China", "type": "originates-from", "target": "Volt Typhoon"},
                {"source": "MSS", "type": "originates-from", "target": "China"},
                {"source": "Through the Wire", "type": "exploits", "target": "CVE-2022-26134"},
            ],
        }
    )
    got = {(r["source"]["name"], r["type"], r["target"]["name"]) for r in ex.relationships}
    assert got == {
        ("Volt Typhoon", "originates-from", "China"),
        ("MSS", "located-at", "China"),
        ("Through the Wire", "targets", "CVE-2022-26134"),
    }


def test_bundle_is_valid_stix_and_only_allowed_relationships():
    ex = parse(SAMPLE)
    bundle, dropped = build_bundle(ex, title="t", published="2024-02-07T00:00:00.000Z")
    stix2.parse(json.dumps(bundle), allow_custom=True)
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert len(report["object_refs"]) == len(bundle["objects"]) - 2  # all but author and report
    assert not dropped


def test_score_perfect_and_alias_match():
    gold = parse(SAMPLE)
    assert score_document(gold, parse(SAMPLE)).headline == 1.0
    pred = parse({"entities": [{"type": "intrusion-set", "name": "BRONZE SILHOUETTE"}]})
    s = score_document(gold, pred)
    assert s.entities.tp == 1 and s.entities.fp == 0  # an alias the document gives


def test_harvest_ids_and_iocs():
    text = (
        "Table 1\nT1059.001 PowerShell\nT1562.001 Impair Defenses\nExploits CVE-2023-3519.\n"
        "C2: 203.0.113.5 and 8.8.8.8, hxxp://bad[.]example[.]com/x\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    )
    h = harvest.harvest(text)
    ids = {e.get("mitre_id") or e["name"] for e in h["entities"]}
    assert ids == {"T1059.001", "T1562.001", "CVE-2023-3519"}
    values = {o["value"] for o in h["observables"]}
    assert "http://bad.example.com/x" in values and "8.8.8.8" in values
    assert "203.0.113.5" not in values  # documentation range, not global


class CutOffBackend:
    """Answers short chunks; cuts the answer off (output limit) on long ones."""

    model_name = "fake"

    def __init__(self):
        self.last_truncated = False
        self.calls = 0

    def complete(self, system, user):
        self.calls += 1
        long = len(user) > 2500
        self.last_truncated = long
        return (
            '{"entities": ['
            if long
            else '{"entities": [{"type": "intrusion-set", '
            '"name": "APT29", "evidence": "APT29"}], "observables": [], "relationships": []}'
        )


def test_engine_splits_a_cut_off_chunk():
    from doc2stix.engine import Engine

    text = (
        "APT29 did things.\n\n" + ("Some paragraph about APT29 and more words. " * 20 + "\n\n") * 4
    )
    backend = CutOffBackend()
    result = Engine(backend, max_chars=4000, harvest=False).extract(text, title="t")
    assert backend.calls > 1
    assert result["_meta"]["errors"] == ""  # every half answered
    assert any(e["name"] == "APT29" for e in result["entities"])


def test_consolidate_applies_the_guidelines():
    text = "Volt Typhoon used Mimikatz.\nIOCs: 203.0.113.9 8.8.4.4 www.cisa.gov 127.0.0.1"
    raw = {
        "entities": [
            {"type": "intrusion-set", "name": "Volt Typhoon", "evidence": "Volt Typhoon"},
            {"type": "tool", "name": "Mimikatz", "evidence": "Mimikatz"},
            {"type": "vulnerability", "name": "CVE-2023-3519", "evidence": "x"},
        ],
        "observables": [
            {"type": "ipv4-addr", "value": "8.8.4.4"},
            {"type": "ipv4-addr", "value": "127.0.0.1"},
            {"type": "domain-name", "value": "www.cisa.gov"},
        ],
        "relationships": [
            {"source": "Volt Typhoon", "type": "uses", "target": "Mimikatz"},
            {"source": "Volt Typhoon", "type": "uses", "target": "CVE-2023-3519"},  # not a rule
        ],
    }
    out = harvest.consolidate(raw, text)
    assert [o["value"] for o in out["observables"]] == ["8.8.4.4"]
    assert out["observables"][0]["indicates"] == ["Volt Typhoon"]
    assert [(r["source"], r["type"], r["target"]) for r in out["relationships"]] == [
        ("Volt Typhoon", "uses", "Mimikatz")
    ]
