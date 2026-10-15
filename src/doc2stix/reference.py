"""Reference data the extraction is checked against.

- OpenCTI's own datasets (sectors, countries, regions), so extracted sectors and
  locations merge with the objects every OpenCTI already has;
- MITRE ATT&CK Enterprise (techniques, groups, software, campaigns), so technique
  IDs are real and known aliases resolve to one name;
- OpenCTI's table of allowed relationships (stixCoreRelationshipsMapping in
  opencti-graphql/src/database/stix.ts, release 7.261008.0).
"""

import json
import re
import unicodedata
from functools import cache
from importlib import resources


def _load(name: str) -> dict:
    return json.loads(resources.files("doc2stix.data").joinpath(name).read_text())


def norm(text: str) -> str:
    """Lower case, no accents, no punctuation, single spaces: for matching names."""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


# Words reports add to a name without making it another entity:
# "DragonForce Ransomware" is DragonForce, "Akira threat actors" is Akira.
GENERIC_SUFFIX = re.compile(
    r" (ransomware( group| gang| variant)?|malware|backdoor|group|gang|"
    r"(threat |cyber |apt |state sponsored )?actors?)$"
)


def name_key(text: str) -> str:
    """Identity of a name: "APT 29", "APT29", "apt-29" are one name, and so are
    "DragonForce Ransomware" and "DragonForce"."""
    n = norm(text)
    stripped = GENERIC_SUFFIX.sub("", n)
    return (stripped or n).replace(" ", "")


@cache
def opencti() -> dict:
    return _load("opencti_reference.json")


@cache
def attack() -> dict:
    return _load("attack_reference.json")


@cache
def allowed_relationships() -> dict[str, list[str]]:
    return _load("opencti_relationships.json")


@cache
def sectors() -> dict[str, str]:
    """Normalized name or alias -> OpenCTI sector name."""
    out = {}
    for s in opencti()["sectors"]:
        for n in [s["name"], *s["aliases"]]:
            out[norm(n)] = s["name"]
    return out


@cache
def locations() -> dict[tuple[str, str], str]:
    """(Country|Region, normalized name or alias) -> OpenCTI location name."""
    out = {}
    for loc in opencti()["locations"]:
        for n in [loc["name"], *loc["aliases"]]:
            out[(loc["type"], norm(n))] = loc["name"]
    return out


# Common ways reports name countries that OpenCTI's names and ISO aliases miss.
# Values are OpenCTI country names (datasets/geography.json).
COUNTRY_SYNONYMS = {
    "united states": "United States of America",
    "u s": "United States of America",
    "america": "United States of America",
    "uk": "United Kingdom of Great Britain and Northern Ireland",
    "united kingdom": "United Kingdom of Great Britain and Northern Ireland",
    "britain": "United Kingdom of Great Britain and Northern Ireland",
    "great britain": "United Kingdom of Great Britain and Northern Ireland",
    "russia": "Russian Federation",
    "south korea": "Republic of Korea",
    "korea": "Republic of Korea",
    "north korea": "Democratic People's Republic of Korea",
    "dprk": "Democratic People's Republic of Korea",
    "iran": "Iran (Islamic Republic of)",
    "prc": "China",
    "people s republic of china": "China",
    "vietnam": "Viet Nam",
    "syria": "Syrian Arab Republic",
    "czech republic": "Czechia",
    "turkiye": "Turkey",
    "etats unis": "United States of America",
    "royaume uni": "United Kingdom of Great Britain and Northern Ireland",
    "russie": "Russian Federation",
    "chine": "China",
    "coree du nord": "Democratic People's Republic of Korea",
    "allemagne": "Germany",
}


def country(name: str) -> str | None:
    n = norm(name)
    known = locations().get(("Country", n))
    if known:
        return known
    return COUNTRY_SYNONYMS.get(n)


def region(name: str) -> str | None:
    return locations().get(("Region", norm(name)))


# How reports name sectors (CISA's 16 critical infrastructure sectors, common
# words, French) -> OpenCTI sector names (datasets/sectors.json).
SECTOR_SYNONYMS = {
    "communications": "Telecommunications",
    "telecommunication": "Telecommunications",
    "telecom": "Telecommunications",
    "transportation": "Transport",
    "transportation systems": "Transport",
    "aviation": "Air transport",
    "maritime": "Maritime transport",
    "water": "Water distribution and supply",
    "water and wastewater": "Water distribution and supply",
    "water and wastewater systems": "Water distribution and supply",
    "information technology": "Technologies",
    "it": "Technologies",
    "technology": "Technologies",
    "government": "Government and administrations",
    "government facilities": "Government and administrations",
    "local government": "Local administrations",
    "military": "Defense ministries (including the military)",
    "defense industrial base": "Defense industry",
    "healthcare": "Health",
    "healthcare and public health": "Health",
    "public health": "Health",
    "hospitals": "Healthcare services",
    "pharmaceutical": "Pharmacy and drugs manufacturing",
    "financial services": "Finance",
    "financial": "Finance",
    "banking": "Banking institutions",
    "critical manufacturing": "Manufacturing",
    "chemical": "Heavy industries",
    "food and agriculture": "Agriculture and agribusiness",
    "agriculture": "Agriculture and agribusiness",
    "nuclear reactors materials and waste": "Nuclear power (civilian use)",
    "oil and gas": "Energy",
    "electric": "Electricity",
    "academia": "Education",
    "higher education": "Universities",
    "media": "Medias and audiovisual",
    "ngos": "Non-Governmental Organizations (NGOs)",
    "non governmental organizations": "Non-Governmental Organizations (NGOs)",
    "think tank": "Think tanks",
    "legal": "Legal consulting",
    "retail": "Retail (distribution)",
    "commercial facilities": "Retail (distribution)",
    "hospitality": "Hospitality",
    "sante": "Health",
    "energie": "Energy",
    "defense": "Defense",
    "administration": "Government and administrations",
    "enseignement": "Education",
}


def sector(name: str) -> str | None:
    n = norm(name)
    n2 = re.sub(r" (sector|sectors|industry|industries|secteur)$", "", n)
    return (
        sectors().get(n) or sectors().get(n2) or SECTOR_SYNONYMS.get(n) or SECTOR_SYNONYMS.get(n2)
    )


@cache
def techniques() -> dict[str, str]:
    """ATT&CK ID -> name ('Command and Scripting Interpreter: PowerShell')."""
    return attack()["techniques"]


@cache
def revoked() -> dict[str, str]:
    """Revoked or renumbered ATT&CK ID -> its current ID (T1562.001 -> T1685)."""
    return attack()["revoked"]


def current_technique(tid: str) -> str | None:
    """The current ATT&CK ID for an ID a document may cite, or None if unknown."""
    tid = revoked().get(tid, tid)
    return tid if tid in techniques() else None


@cache
def technique_by_name() -> dict[str, str]:
    """Normalized technique name (with or without its parent) -> ATT&CK ID."""
    out: dict[str, str] = {}
    for tid, name in techniques().items():
        out.setdefault(norm(name), tid)
        if ": " in name:
            out.setdefault(norm(name.split(": ", 1)[1]), tid)
    return out


@cache
def canonical_names() -> dict[str, str]:
    """Normalized alias of an ATT&CK group, software or campaign -> its ATT&CK name."""
    out: dict[str, str] = {}
    for kind in ("groups", "software", "campaigns"):
        for x in attack()[kind]:
            for n in [x["name"], *x["aliases"]]:
                out.setdefault(norm(n), x["name"])
    return out
