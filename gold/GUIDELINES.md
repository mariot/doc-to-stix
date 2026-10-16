# Annotation guidelines

These rules define the gold extractions (`gold/*.json`), and the engine's prompt
states the same rules: a score measures how well a system follows them. When a
rule changes, the gold changes with it and the eval version is bumped.

The format is the compact extraction described in `src/doc2stix/compact.py`;
`doc2stix build` turns it into a STIX 2.1 bundle for OpenCTI.

## Principles

1. **Only what the document says.** No background knowledge: no alias, target,
   technique or attribution that the document does not state. If the document
   says "Volt Typhoon (also known as BRONZE SILHOUETTE)", both names are there;
   if it only says "Volt Typhoon", there is no alias.
2. **What the document is about.** The activity the report describes, not its
   bibliography, its authors, or examples given for context ("like the 2017
   NotPetya attack...") unless the report ties them to the activity.
3. **Evidence.** Every entity and every relationship carries an `evidence`
   quote: a short passage (at most ~200 characters) copied verbatim from the
   document text (`corpus/text/<id>.txt`), that states it. Observables need no
   quote: their value must appear in the text (defanged forms count).

## Entities

| type | what | name |
|---|---|---|
| `intrusion-set` | a named cluster of malicious activity: APT29, Volt Typhoon, Scattered Spider, "LockBit affiliates" when the document treats them as a group | as written; other names the document gives go in `aliases`. Groups the document keeps apart stay apart, even if ATT&CK lists one as an alias of the other |
| `threat-actor` | a real-world organization or person behind activity: "Russian GRU Unit 29155", "China's Ministry of State Security" | as written |
| `campaign` | a named operation, or a dated wave the document names | as written |
| `malware` | malicious software, including ransomware families and malware-as-a-service | as written; versions are part of the name only if the document distinguishes them ("LockBit 3.0") |
| `tool` | legitimate or dual-use software abused by the actor (Mimikatz, PsExec, AnyDesk, Impacket) | if the software is in MITRE ATT&CK, follow its ATT&CK type (Cobalt Strike is malware there) |
| `attack-pattern` | a MITRE ATT&CK technique (Enterprise, Mobile or ICS) the document attributes to the activity: cited by ID, or described in prose when exactly one technique clearly fits ("password spraying" T1110.003, "created a scheduled task" T1053.005, "deleted volume shadow copies" T1490); not for vague behaviour | `mitre_id` is required, as the document writes it (an ID revoked in later ATT&CK versions is mapped to the current one); sub-technique when the document gives it |
| `vulnerability` | a CVE the activity exploits or targets | the CVE ID |
| `sector` | a targeted sector | an OpenCTI sector name (`src/doc2stix/data/opencti_reference.json`): the most specific one that fits ("Electricity" rather than "Energy" if the document says electric utilities) |
| `country`, `region` | a targeted country or region, or the country an actor originates from | an OpenCTI location name |
| `organization` | a named victim organization (rare in public advisories) | as written |

Not entities: the authoring agencies and their countries (CISA, the FBI, ANSSI,
"United States" as an author), security vendors cited as sources, generic words
("ransomware", "a backdoor", "web shell") without a name, legitimate products
that are only targets (they go into a CVE or a sector, not a tool), and file
names ("stage1.exe", "Client.exe") unless the document uses one as the name of
the family. The authors' country is an entity when it is a target ("victims in
the United States"), only not as an author.

Ransomware: the malware is the ransomware family ("Akira"); the group operating
it is an intrusion-set only when the document speaks of the group ("Akira
affiliates", "the Akira group") — then the intrusion-set uses the malware.

## Observables

IOCs the document lists as malicious: `ipv4-addr`, `ipv6-addr`, `domain-name`,
`url`, `email-addr`, `file` (a hash, with `hash`: MD5, SHA-1, SHA-256 or
SHA-512). Values as written, defanged or not (they are refanged and normalized).
Not observables: private or documentation addresses, the agency's own contacts,
example values, file names without a hash.

`indicates`: the names of the entities (intrusion-set, malware, campaign) the
document ties the IOC to. A table titled "Volt Typhoon IOCs" makes every IOC in
it indicate Volt Typhoon.

Matching: entities are matched by name with spacing and punctuation ignored
("APT 29" = "APT29") or by an alias the document gives; attack-patterns by
current ATT&CK ID.

## Relationships

`source`, `type`, `target`; the ends are names (or ATT&CK IDs, or observable
values). Only these, and only when the document states them:

| source | type | target |
|---|---|---|
| intrusion-set, threat-actor, campaign, malware, tool | `uses` | attack-pattern |
| intrusion-set, threat-actor, campaign | `uses` | malware, tool |
| intrusion-set, threat-actor, campaign, malware | `targets` | sector, country, region, organization |
| intrusion-set, threat-actor, campaign | `targets` | vulnerability (the actor exploits the CVE) |
| malware | `exploits` | vulnerability |
| tool | `targets` | vulnerability (OpenCTI has no "tool exploits") |
| intrusion-set | `originates-from` | country |
| threat-actor | `located-at` | country |
| intrusion-set | `attributed-to` | threat-actor |
| campaign | `attributed-to` | intrusion-set, threat-actor |
| malware | `variant-of` | malware |

An ATT&CK table in an advisory ("Table 1: ATT&CK techniques used by X") makes
X `uses` each technique of the table. If the advisory describes several actors
or several malware families, link each technique to the one the text gives it
to; when the document does not say, to the main subject of the advisory.
