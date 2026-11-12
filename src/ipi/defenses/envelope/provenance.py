"""Provenance tagger: for each argument value, where could it have come from?

Provenance is a SIGNAL here, not the gate. The checker consults it only for sink args the envelope
left unpinned (Constraint.kind == "any").

Labels:
  user            - value appears in the user's query
  record:<name>   - value IS a structured field of a record returned by tool <name> (a transaction's sender,
                    amount or id), in a field the taxonomy does not mark as free text. Such fields are written
                    by the system, not by whoever authored the content, so they are not attacker text.
  tool:<name>     - value appears somewhere in the output of tool <name> (untrusted: may be attacker-controlled)
  model           - appears nowhere: the model generated it
A value can match several sources; we return all, user first.

Field-level trust (v2). Substring-level taint treats a whole tool output as attacker-controlled, which blocks
every task that acts on data it looked up ("refund whoever just paid me"). But in a record the attacker writes
only the free-text fields (a transaction's subject, a message body). `record_values` parses the output the tool
actually returned - never the text inside a field - so a payload saying "sender: <attacker IBAN>" inside a
subject stays a string in a free-text field and gains nothing. Tools without a `free_text` declaration in the
taxonomy (files, web pages) are free text as a whole.

Known limitation (say this in the thesis): substring matching is a heuristic. It misses transformed values
(paraphrase, re-formatting) and over-matches short strings. Record trust assumes the attacker cannot create
records (e.g. send a real payment from their own account); where they can, a record field is theirs too.
"""
from __future__ import annotations

import re
from typing import Any

import yaml

MIN_LEN = 4  # shorter values are too ambiguous to trace


def _leaves(v: Any) -> list[str]:
    if isinstance(v, dict):
        return [x for vv in v.values() for x in _leaves(vv)]
    if isinstance(v, (list, tuple, set)):
        return [x for vv in v for x in _leaves(vv)]
    return [] if v is None else [str(v)]


def canon(v: Any) -> str:
    """Canonical form for equality: numbers by value (10 == 10.0 == '10.00'), everything else case-folded."""
    s = str(v).strip().lower()
    if isinstance(v, bool):
        return s
    try:
        return repr(float(s))
    except ValueError:
        return s


_NUM = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w]|\.\d)")


def stated_by_user(leaf: Any, user_query: str) -> bool:
    """True if the user literally wrote this value: a number equal to a number in the query, or a string of at
    least MIN_LEN characters that appears in the query as a whole phrase (not inside a longer word)."""
    s, q = str(leaf).strip().lower(), user_query.lower()
    if not s:
        return False
    try:
        x = float(s)
        return any(float(m) == x for m in _NUM.findall(q))
    except ValueError:
        pass
    if len(s) < MIN_LEN:
        return False
    return re.search(r"(?<!\w)" + re.escape(s) + r"(?!\w)", q) is not None


def record_values(text: str, free_text: tuple[str, ...]) -> set[str]:
    """Canonical leaves of the structured (non-free-text) fields of a record-returning tool's output.
    Empty if the output is not a mapping / list of mappings."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return set()
    out: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if str(k) not in free_text:
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif v is not None and str(v).strip():
            out.add(canon(v))

    if isinstance(data, dict) or (isinstance(data, list) and all(isinstance(x, dict) for x in data)):
        walk(data)
    return out


def sources_of(value: Any, user_query: str, tool_outputs: list[tuple[str, str]],
               records: list[set[str]] | None = None) -> dict[str, list[str]]:
    """Map each leaf string of `value` to its candidate sources. `records[i]` (optional) is
    record_values() of tool_outputs[i] for tools the taxonomy declares as record-returning, else empty."""
    q = user_query.lower()
    out: dict[str, list[str]] = {}
    for leaf in _leaves(value):
        s = leaf.strip().lower()
        srcs = []
        if records:
            c = canon(leaf)
            srcs += [f"record:{tool}" for (tool, _), rec in zip(tool_outputs, records) if c in rec]
        if len(s) < MIN_LEN:
            srcs.append("short")
        else:
            if s in q:
                srcs.append("user")
            for tool, text in tool_outputs:
                if s in text.lower():
                    srcs.append(f"tool:{tool}")
            if not srcs:
                srcs.append("model")
        out[leaf] = sorted(set(srcs), key=lambda x: (x != "user", x))
    return out


def untrusted_only(srcs: dict[str, list[str]]) -> list[str]:
    """Leaves whose ONLY support is free text in tool outputs (no user support, not a record field)."""
    return [leaf for leaf, s in srcs.items()
            if "user" not in s and not any(x.startswith("record:") for x in s) and any(x.startswith("tool:") for x in s)]
