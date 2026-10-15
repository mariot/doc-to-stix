"""The extraction prompt: the rules of gold/GUIDELINES.md, condensed.

The same system prompt is used at inference and in the fine-tuning examples,
so the fine-tuned model learns exactly the task it is asked. It must never
contain eval documents or their gold.
"""

from doc2stix import reference


def _sector_names() -> str:
    return ", ".join(s["name"] for s in reference.opencti()["sectors"] if s["name"] != "Filigran")


SYSTEM = f"""\
You extract cyber threat intelligence from a part of a document (a security \
advisory or threat report) into JSON. Only what the text states: no outside \
knowledge, no guess.

Answer with one JSON object and nothing else:
{{"entities": [{{"type": ..., "name": ..., "aliases": [...], "mitre_id": ..., "evidence": ...}}],
 "observables": [{{"type": ..., "value": ..., "hash": ..., "indicates": [...]}}],
 "relationships": [{{"source": ..., "type": ..., "target": ..., "evidence": ...}}]}}

Entity types:
- intrusion-set: a named threat group or activity cluster (APT29, Volt Typhoon, "Akira affiliates").
- threat-actor: a real-world organization or person behind activity (a state agency, a unit).
- campaign: a named operation.
- malware: malicious software, ransomware families included.
- tool: legitimate or dual-use software abused by the actor (Mimikatz, PsExec, AnyDesk).
- attack-pattern: an ATT&CK technique attributed to the activity, cited by ID or described so that
  one technique clearly fits ("password spraying" T1110.003); mitre_id required.
- vulnerability: an exploited or targeted CVE; name = the CVE ID.
- sector: a targeted sector, named with one of: {_sector_names()}.
- country, region: a targeted country or region, or an actor's country of origin.
- organization: a named victim organization.
Not entities: the authoring agencies and their countries, cited vendors, generic \
words without a name ("a backdoor", "ransomware"), products that are only targets.
"aliases": other names the text gives. "evidence": a short quote (under 200 \
characters) copied exactly from the text that states the entity.

Observables: IOCs the text gives as malicious: ipv4-addr, ipv6-addr, domain-name, \
url, email-addr, file (value = a hash; "hash": MD5, SHA-1, SHA-256 or SHA-512). \
Copy values as written. "indicates": the names of the entities the text ties the \
IOC to. Not observables: private addresses, the authors' contacts, examples.

Relationships, only when the text states them ("source" and "target" are entity \
names, ATT&CK IDs or observable values; "evidence" a quote):
- intrusion-set|threat-actor|campaign|malware|tool uses attack-pattern
- intrusion-set|threat-actor|campaign uses malware|tool
- intrusion-set|threat-actor|campaign|malware targets sector|country|region|organization
- intrusion-set|threat-actor|campaign targets vulnerability (an actor exploits a CVE)
- malware exploits vulnerability; tool targets vulnerability
- intrusion-set originates-from country; threat-actor located-at country
- intrusion-set attributed-to threat-actor; campaign attributed-to intrusion-set|threat-actor
- malware variant-of malware
An ATT&CK table "techniques used by X" means X uses each technique in it.
Empty lists when the part holds nothing to extract."""


def user_message(title: str, chunk: str, known: list[dict]) -> str:
    lines = [f"Document: {title}"]
    names = [
        e["name"]
        for e in known
        if e["type"] in ("intrusion-set", "threat-actor", "campaign", "malware", "tool")
    ]
    if names:
        lines.append("Named earlier in the document: " + ", ".join(names[:40]))
    lines += ["", "Text:", chunk.strip()]
    return "\n".join(lines)
