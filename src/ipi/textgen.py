"""Plain text-completion helper for *auxiliary* LLMs (envelope extractor, policy generator, attacker).
Separate from the agent backbone so each can use a different (usually cheaper) model.

Cached on disk: identical (provider, model, system, prompt, salt) never hits the API twice.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from pathlib import Path

_DB_LOCK = threading.Lock()
_DB: sqlite3.Connection | None = None


def _db(path: str = "results/cache/textgen.sqlite") -> sqlite3.Connection:
    global _DB
    if _DB is None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        _DB = sqlite3.connect(path, check_same_thread=False)
        _DB.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT)")
    return _DB


def complete(prompt: str, *, provider: str, model: str, system: str = "", temperature: float = 0.0,
             max_tokens: int = 2048, salt: str = "", use_cache: bool = True) -> str:
    key = hashlib.sha256(json.dumps([provider, model, system, prompt, temperature, salt]).encode()).hexdigest()
    if use_cache:
        with _DB_LOCK:
            row = _db().execute("SELECT v FROM c WHERE k=?", (key,)).fetchone()
        if row:
            return row[0]

    if provider == "anthropic":
        import anthropic
        r = anthropic.Anthropic().messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature, system=system or anthropic.NOT_GIVEN,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in r.content if b.type == "text")
    elif provider in ("openai", "openai-compat"):
        import openai
        client = openai.OpenAI() if provider == "openai" else openai.OpenAI(
            base_url=os.environ["OPENAI_COMPAT_BASE_URL"], api_key=os.environ.get("OPENAI_COMPAT_API_KEY", "EMPTY"))
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        r = client.chat.completions.create(model=model, messages=msgs, temperature=temperature, max_tokens=max_tokens)
        text = r.choices[0].message.content or ""
    else:
        raise ValueError(f"textgen: unsupported provider {provider!r}")

    if use_cache:
        with _DB_LOCK:
            _db().execute("INSERT OR REPLACE INTO c VALUES (?,?)", (key, text))
            _db().commit()
    return text


def extract_json(text: str):
    """Pull the first JSON object/array out of a model response (handles ```json fences)."""
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    start = min([i for i in (text.find("{"), text.find("[")) if i != -1], default=-1)
    if start == -1:
        raise ValueError("no JSON found in model output")
    return json.JSONDecoder().raw_decode(text[start:])[0]
